import json
import re
import os
import requests
import traceback
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import MongoClient
from flask_cors import cross_origin

# Load environment variables
load_dotenv(override=True)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")

# Flask App Setup
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Check if environment variables are set
if not GEMINI_API_KEY or not MONGO_URI:
    raise ValueError("❌ Missing environment variables: GEMINI_API_KEY or MONGO_URI")

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI)
    db = client["quiz_db"]  # Database Name
    collection = db["questions"]  # Collection Name
    users_collection = db["users"]  # Collection for Users
    print("✅ MongoDB connected successfully!")
except Exception as e:
    print("🔥 MongoDB Connection Error:", e)
    raise e

def extract_details(email):
    """Extracts roll number and determines user role from email."""
    match = re.match(r"^(\d{12})@gvpce\.ac\.in$", email)  # Match exactly 12 digits
    if match:
        roll_no = match.group(1)
        role = "student"  # Default role
        return {"roll_no": roll_no, "role": role}
    return None  # Invalid email format
def ensure_admin_exists():
    """Ensure the administrator account is pre-existing in the database."""
    admin_email = "admin@gvpce.ac.in"
    admin_password = "Nikhil@834134"
    
    existing_admin = users_collection.find_one({"email": admin_email})
    
    if not existing_admin:
        users_collection.insert_one({
            "email": admin_email,
            "password": admin_password,  # Consider hashing for security
            "username": "Admin",
            "role": "admin"
        })
        print("✅ Admin account created.")
    else:
        print("🔹 Admin account already exists.")

# Ensure admin user is in the database
ensure_admin_exists()

# 🔹 SIGNUP Route
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        print("📩 Received signup request:", data)  # Debugging log

        email = data.get("email")
        password = data.get("password")
        username = data.get("username")  # Ensure username is received

        if not email or not password or not username:
            print("❌ Missing required fields!")  # Debugging log
            return jsonify({"error": "Email, password, and username are required!"}), 400

        details = extract_details(email)
        if not details:
            print("🚫 Invalid email format!")  # Debugging log
            return jsonify({"error": "Invalid email format. Use @gvpce.ac.in"}), 400

        roll_no = details["roll_no"]
        role = details["role"]

        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            print("⚠️ User already exists!")  # Debugging log
            return jsonify({"error": "User already exists! Please log in."}), 409

        new_user = {
            "email": email,
            "password": password,  # Consider hashing for security
            "username": username,  # Store username in DB
            "roll_no": roll_no,
            "role": role
        }
        
        result = users_collection.insert_one(new_user)
        print("✅ User created successfully!", result.inserted_id)  # Debugging log

        return jsonify({"message": "Signup successful!", "email": email, "username": username}), 201

    except Exception as e:
        print("🔥 ERROR during signup:", str(e))  # Debugging log
        return jsonify({"error": str(e)}), 500

@app.route('/get-user-info', methods=['GET'])
def get_user_info():
    if 'student_name' in session and 'roll_no' in session:
        return jsonify({
            'student_name': session['student_name'],
            'roll_no': session['roll_no']
        })
    else:
        return jsonify({'error': 'User not logged in'}), 401
    
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required!"}), 400

        user = users_collection.find_one({"email": email})

        if not user:
            return jsonify({"error": "User not found! Please sign up first."}), 404

        if user["password"] != password:
            return jsonify({"error": "Incorrect password!"}), 401

        # Check if the user is admin
        if email == "admin@gvpce.ac.in":
            return jsonify({
                "message": "Admin Login successful!",
                "redirect": "help.html",
                "email": email,
                "username": user["username"]
            }), 200

        # Regular student login
        return jsonify({
            "message": "Login successful!",
            "redirect": "student.html",
            "email": email,
            "username": user["username"],
            "roll_no": user.get("roll_no", "")  # Avoid error if roll_no is missing
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 🔹 GET USERS Route
@app.route('/get-users', methods=['GET'])
def get_users():
    try:
        users = list(users_collection.find({}, {"_id": 0, "password": 0}))  # Hide passwords
        return jsonify({"users": users})
    except Exception as e:
        print("🔥 ERROR fetching users:", str(e))
        return jsonify({"error": str(e)}), 500
    
@app.route('/reset-users', methods=['POST'])
def reset_users():
    """Deletes all users from the database."""
    try:
        deleted_count = users_collection.delete_many({}).deleted_count
        print(f"✅ Deleted {deleted_count} users from the database.")

        return jsonify({"message": f"Deleted {deleted_count} users successfully!"}), 200

    except Exception as e:
        print("🔥 ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/generate-quiz', methods=['POST'])
def generate_quiz():
    """Reset quiz and generate new questions using Gemini API, storing them in MongoDB."""
    try:
        data = request.get_json()
        topic = data.get("topic")
        difficulty = data.get("difficulty")
        num_questions = data.get("num_questions", 5)  # Default to 5

        if not topic or not difficulty or not isinstance(num_questions, int) or num_questions <= 0:
            return jsonify({"error": "Invalid topic, difficulty, or num_questions"}), 400

        print(f"📝 Generating {num_questions} questions on '{topic}' at {difficulty} difficulty...")

        # Define AI prompt
        prompt = (
            f"Generate {num_questions} multiple-choice questions on {topic} at {difficulty} difficulty. "
            "Each question must include: 'question', 'options' (4 choices), and 'correct_answer'. "
            "Return a JSON array in this format:\n"
            "[{'question': '...', 'options': ['A', 'B', 'C', 'D'], 'correct_answer': '...'}]"
        )

        # Send request to Gemini API
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"
        headers = {"Content-Type": "application/json"}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        response = requests.post(url, json=payload, headers=headers)
        gemini_response = response.json()

        print("🤖 Gemini API Response:", json.dumps(gemini_response, indent=2))

        # Extract response text
        raw_text = gemini_response.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()

        if not raw_text:
            return jsonify({"error": "AI response is empty"}), 500

        # Clean JSON response
        json_text = re.sub(r"```json\n|\n```", "", raw_text).strip()

        try:
            quiz_questions = json.loads(json_text)

            if not isinstance(quiz_questions, list) or len(quiz_questions) != num_questions:
                return jsonify({"error": f"AI did not return {num_questions} questions", "raw_response": raw_text}), 500

            for q in quiz_questions:
                if not all(key in q for key in ("question", "options", "correct_answer")):
                    return jsonify({"error": "Invalid question format from AI"}), 500
                if not isinstance(q["options"], list) or len(q["options"]) != 4:
                    return jsonify({"error": "Invalid options format from AI"}), 500

            # 🚀 Reset quiz before inserting new questions
            collection.delete_many({})
            print("🔄 Quiz reset! Previous questions deleted.")

            # Add metadata before inserting into DB
            for q in quiz_questions:
                q["topic"] = topic
                q["difficulty"] = difficulty

            # Insert all questions at once (optimized)
            collection.insert_many(quiz_questions)
            print(f"✅ Stored {num_questions} new questions in MongoDB.")

            return jsonify({"questions": quiz_questions})

        except json.JSONDecodeError:
            return jsonify({"error": "AI returned invalid JSON format", "raw_response": raw_text}), 500

    except Exception as e:
        print("🔥 ERROR:", str(e))
        print(traceback.format_exc())  # Debugging
        return jsonify({"error": str(e)}), 500

@app.route('/get-questions', methods=['GET'])
def get_questions():
    """Retrieve stored questions."""
    try:
        questions = list(collection.find({}, {"_id": 0}))

        return jsonify({
            "questions": questions,
            "total_questions": len(questions)
        })

    except Exception as e:
        print("🔥 ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/reset-quiz', methods=['POST'])
def reset_quiz():
    """Clear all questions and scores from the database."""
    try:
        # Delete all questions from the 'questions' collection
        questions_collection = db["questions"]
        deleted_questions_count = questions_collection.delete_many({}).deleted_count
        print(f"✅ {deleted_questions_count} questions deleted successfully!")

        # Delete all scores from the 'scores' collection
        scores_collection = db["scores"]
        deleted_scores_count = scores_collection.delete_many({}).deleted_count
        print(f"✅ {deleted_scores_count} scores deleted successfully!")

        # Return success message with counts of deleted data
        return jsonify({
            "message": f"Quiz reset successfully! {deleted_questions_count} questions and {deleted_scores_count} scores cleared."
        })
    except Exception as e:
        print("🔥 ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route('/submit-all-changes', methods=['POST'])
def submit_all_changes():
    """Replace all questions in the database with the updated ones."""
    try:
        data = request.get_json()  # Get updated questions from frontend
        updated_questions = data.get("questions")

        print("🔹 Received request to update questions:", updated_questions)  # Debug log

        if not isinstance(updated_questions, list) or len(updated_questions) == 0:
            print("❌ Invalid data format received!")
            return jsonify({"error": "Invalid or empty question list"}), 400

        # 🔄 Reset database before inserting new questions
        deleted_count = collection.delete_many({}).deleted_count
        print(f"🗑 Deleted {deleted_count} old questions.")

        # 📝 Insert new questions
        insert_result = collection.insert_many(updated_questions)
        print(f"✅ Inserted {len(insert_result.inserted_ids)} new questions.")

        return jsonify({"message": "All changes saved successfully!"})

    except Exception as e:
        print("🔥 ERROR:", str(e))
        return jsonify({"error": str(e)}), 500
    
@app.route('/submit-score', methods=['POST'])
def submit_score():
    try:
        data = request.json
        print("📩 Received score submission:", data)  # Debug log

        student_name = data.get("student_name")
        roll_no = data.get("roll_no")
        score = data.get("score")
        total_questions = data.get("total_questions")

        if not student_name or not roll_no or score is None or total_questions is None:
            print("❌ Missing score data!")  # Debug log
            return jsonify({"error": "Invalid score data"}), 400

        scores_collection = db["scores"]

        # ❌ STRICT CHECK: If the roll number or name already exists, reject submission
        existing_student = scores_collection.find_one({
            "$or": [{"student_name": student_name}, {"roll_no": roll_no}]
        })

        if existing_student:
            print("🚫 This student has already taken the quiz!")  # Debug log
            return jsonify({"error": "You have already taken the quiz!"}), 403

        # ✅ Store new score
        new_score = {
            "student_name": student_name,
            "roll_no": roll_no,
            "score": score,
            "total_questions": total_questions,
            "timestamp": data.get("timestamp")  # Add timestamp for tracking
        }

        scores_collection.insert_one(new_score)  # Insert into DB
        print("✅ Score stored in MongoDB!")  # Debug log

        return jsonify({"message": "Score submitted successfully!", "data": new_score}), 201

    except Exception as e:
        print("🔥 ERROR submitting score:", str(e))
        return jsonify({"error": str(e)}), 500
@app.route('/has-attempted-quiz', methods=['POST'])
def has_attempted_quiz():
    try:
        data = request.json
        student_name = data.get("student_name")
        roll_no = data.get("roll_no")

        if not student_name or not roll_no:
            return jsonify({"error": "Invalid student details"}), 400

        # 🔎 Check if student has already taken the quiz
        existing_attempt = db["scores"].find_one({
            "$or": [{"student_name": student_name}, {"roll_no": roll_no}]
        })

        if existing_attempt:
            return jsonify({"attempted": True})  # ✅ Student has already attempted
        else:
            return jsonify({"attempted": False})  # ❌ Student can take the quiz

    except Exception as e:
        print("🔥 ERROR checking quiz attempt:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/get-scores", methods=["GET"])
def get_scores():
    try:
        # Ensure scores_collection is correctly referenced
        scores_collection = db["scores"]
        
        scores = scores_collection.find()
        scores_list = []

        for score in scores:
            scores_list.append({
                "id": str(score["_id"]),  # Convert ObjectId to string
                "student_name": score.get("student_name", "Unknown"),
                "roll_no": score.get("roll_no", "N/A"),  # Ensure roll_no is retrieved
                "score": score.get("score", 0),
                "total_questions": score.get("total_questions", 0)
            })

        return jsonify({"scores": scores_list})
    except Exception as e:
        print("🔥 ERROR fetching scores:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/check-student', methods=['POST'])
def check_student():
    data = request.json
    student_name = data.get("student_name")
    roll_no = data.get("roll_no")

    # Check if the name OR roll number exists in the database
    existing_student = db.scores.find_one({
        "$or": [{"student_name": student_name}, {"roll_no": roll_no}]
    })

    if existing_student:
        return jsonify({"error": "Name or Roll Number already exists"}), 403  # 🚫 Forbidden

    return jsonify({"message": "Valid entry"}), 200  # ✅ OK

if __name__ == '__main__':
    app.run(debug=True, port=5000)

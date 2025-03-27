import json
import re
import os
import base64
import uuid
import bcrypt
import requests
import traceback
from flask import Flask, request, jsonify, session, render_template, url_for
from flask_cors import CORS
from flask_pymongo import PyMongo
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId
from flask_cors import cross_origin
from werkzeug.security import generate_password_hash, check_password_hash
from bson import Binary
# Load environment variables
load_dotenv(override=True)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")
# Flask App Setup
# Flask App Setup
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")  # Change to a strong random key
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
import bcrypt
from flask import request, jsonify

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")
        username = data.get("name")
        roll_no = data.get("roll_no")

        if not email or not password or not username or not roll_no:
            return jsonify({"error": "All fields are required!"}), 400

        # 🔎 Ensure `users_collection` is properly defined
        users_collection = db["users"]

        # 🔎 Check if user already exists (by email or roll_no)
        existing_user = users_collection.find_one({"$or": [{"email": email}, {"roll_no": roll_no}]})
        if existing_user:
            return jsonify({"error": "User already exists! Please log in."}), 409

        # ✅ Hash the password before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # ✅ Store user with hashed password
        new_user = {
            "email": email,
            "password": hashed_password.decode('utf-8'),  # Store as string
            "username": username,
            "roll_no": roll_no,
            "role": "student"
        }

        users_collection.insert_one(new_user)
        return jsonify({"message": "Signup successful!"}), 201

    except Exception as e:
        print("🔥 ERROR during signup:", str(e))
        return jsonify({"error": "Internal Server Error"}), 500


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

        # ✅ Check password using bcrypt
        if not bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
            return jsonify({"error": "Incorrect password!"}), 401

        # ✅ Admin check
        if email == "admin@gvpce.ac.in":
            return jsonify({
                "message": "Admin Login successful!",
                "redirect": "main.html",
                "email": email,
                "username": user["username"]
            }), 200

        # ✅ Student login
        return jsonify({
            "message": "Login successful!",
            "redirect": "main.html",
            "email": email,
            "username": user["username"],
            "roll_no": user.get("roll_no", "")
        }), 200

    except Exception as e:
        print("🔥 ERROR during login:", str(e))
        return jsonify({"error": "Internal Server Error"}), 500

    
@app.route('/get-users', methods=['GET'])
def get_users():
    try:
        users_collection = db["users"]  # Ensure correct collection reference
        
        # Fetch users and exclude `_id` field
        users = list(users_collection.find({}, {"_id": 0, "password": 0}))  # Exclude passwords for security

        if not users:
            return jsonify({"message": "No users found"}), 404

        return jsonify({"users": users}), 200

    except Exception as e:
        print("🔥 ERROR fetching users:", str(e))
        return jsonify({"error": "Internal Server Error"}), 500

    
@app.route('/reset-users', methods=['POST'])
def reset_users():
    """Deletes all users except the admin from the database."""
    try:
        # Delete all users except the admin
        deleted_count = users_collection.delete_many({"email": {"$ne": "admin@gvpce.ac.in"}}).deleted_count
        print(f"✅ Deleted {deleted_count} non-admin users from the database.")

        return jsonify({"message": f"Deleted {deleted_count} users successfully, Admin remains!"}), 200

    except Exception as e:
        print("🔥 ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/view_question/<question_id>')
def view_question(question_id):
    question = collection.find_one({"_id": ObjectId(question_id)})  
    return render_template("question.html", question=question)

@app.route('/create_question', methods=['POST'])
def create_question():
    data = request.json
    return jsonify({"message": "Question added!", "data": data})
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

        # **Fixed AI Prompt**
        prompt = (
            f"Generate {num_questions} multiple-choice questions on {topic} at {difficulty} difficulty. "
            "Each question must include:\n"
            "- 'question': The full question text.\n"
            "- 'options': A list of 4 answer choices as full text.\n"
            "- 'correct_answer': The full text of the correct answer (not just 'A', 'B', etc.).\n"
            "Return a JSON array in this format:\n"
            "[{'question': '...', 'options': ['Option 1', 'Option 2', 'Option 3', 'Option 4'], 'correct_answer': 'Option X'}]"
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

                # **Ensure correct_answer contains full text, not just "A", "B", etc.**
                correct_answer = q["correct_answer"].strip()
                options = [opt.strip() for opt in q["options"]]

                if correct_answer in ["A", "B", "C", "D"]:
                    correct_index = ord(correct_answer) - ord("A")  # Convert "A" -> 0, "B" -> 1, etc.
                    if 0 <= correct_index < len(options):
                        q["correct_answer"] = options[correct_index]  # Replace with full answer text
                    else:
                        return jsonify({"error": f"Invalid correct answer index for question: {q}"}), 500

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


from flask import send_from_directory

UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")  # Ensure absolute path
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded images."""
    print(f"📤 Serving file: {filename}")
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route('/get-questions', methods=['GET'])
def get_questions():
    """Retrieve stored questions along with their base64 image URLs if applicable."""
    try:
        questions = list(collection.find({}, {"_id": 0}))  # Fetch all questions

        for question in questions:
            # ✅ Convert question image to Base64 if it exists
            if "image" in question and isinstance(question["image"], Binary):
                question["image"] = f"data:image/png;base64,{base64.b64encode(question['image']).decode('utf-8')}"

            # ✅ Process option images
            if "option_images" in question and isinstance(question["option_images"], dict):
                for key, img in question["option_images"].items():
                    if isinstance(img, Binary):  
                        question["option_images"][key] = f"data:image/png;base64,{base64.b64encode(img).decode('utf-8')}"
                    elif isinstance(img, str) and img.startswith("data:image"):  
                        question["option_images"][key] = img  # Already Base64, keep as is
                    else:
                        question["option_images"][key] = None  # No image found

        # 🔍 Debugging: Print the JSON before returning
        print("✅ Processed Questions Data:", questions)

        return jsonify({"questions": questions, "total_questions": len(questions)})

    except Exception as e:
        print("🔥 ERROR:", str(e))
        return jsonify({"error": "Internal Server Error"}), 500


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

from bson import ObjectId

@app.route('/submit-score', methods=['POST'])
def submit_score():
    try:
        data = request.json
        print("📩 Received score submission:", data)  # Debug log

        # Extract data fields
        student_name = data.get("student_name")
        roll_no = data.get("roll_no")
        score = data.get("score")
        total_questions = data.get("total_questions")
        topic = data.get("topic")  # Add topic to track quiz attempts
        timestamp = data.get("timestamp")

        # ✅ Check for missing fields
        if not all([student_name, roll_no, score is not None, total_questions is not None, topic, timestamp]):
            print("❌ Missing score data!")  # Debug log
            return jsonify({"error": "Invalid score data. All fields are required!"}), 400

        scores_collection = db["scores"]

        # 🔎 STRICT CHECK: If the roll number already exists for the same topic, reject submission
        existing_attempt = scores_collection.find_one({"roll_no": roll_no, "topic": topic})

        if existing_attempt:
            print("🚫 This roll number has already attempted the quiz for this topic!")  # Debug log
            return jsonify({"error": "You have already attempted this quiz!"}), 403

        # ✅ Store new score
        new_score = {
            "student_name": student_name,
            "roll_no": roll_no,
            "score": score,
            "total_questions": total_questions,
            "topic": topic,  # Save topic for future checks
            "timestamp": timestamp  # Store timestamp
        }

        result = scores_collection.insert_one(new_score)  # Insert into DB

        # ✅ Convert ObjectId to string before returning response
        new_score["_id"] = str(result.inserted_id)

        print("✅ Score stored in MongoDB!")  # Debug log
        return jsonify({"message": "Score submitted successfully!", "data": new_score}), 201

    except Exception as e:
        print("🔥 ERROR submitting score:", str(e))
        return jsonify({"error": "Internal Server Error"}), 500


@app.route('/store-questions', methods=['POST'])
def store_questions():
    data = request.json
    questions = data.get("questions", [])

    processed_questions = []
    
    for question in questions:
        question["image"] = process_image(question.get("image", ""), "question")

        # ✅ Process option images
        if "option_images" in question and isinstance(question["option_images"], dict):
            processed_option_images = {}
            for key, img in question["option_images"].items():
                processed_option_images[key] = process_image(img, f"option-{key}")
            question["option_images"] = processed_option_images

        question["answer_image"] = process_image(question.get("answer_image", ""), "answer")

        processed_questions.append(question)

    if processed_questions:
        collection.insert_many(processed_questions)

    return jsonify({"message": "Questions stored successfully"}), 200

UPLOAD_FOLDER = "uploads"

def save_base64_image(data, prefix):
    """Save a base64 image and return the base64 string to store in MongoDB."""
    try:
        if "," not in data:
            print("❌ Invalid base64 format!")
            return None

        # Extract the base64 data (remove metadata)
        image_data = data.split(",")[1]

        # Validate base64 format
        try:
            image_bytes = base64.b64decode(image_data)
        except Exception as e:
            print("🔥 ERROR decoding Base64:", str(e))
            return None

        # Convert image bytes back to a Base64 string (to be stored in MongoDB)
        encoded_string = base64.b64encode(image_bytes).decode("utf-8")
        return f"data:image/png;base64,{encoded_string}"

    except Exception as e:
        print("🔥 ERROR saving image:", str(e))
        return None
@app.route('/test-save-image', methods=['POST'])
def test_save_image():
    """Test saving a base64 image."""
    data = request.json
    base64_image = data.get("image")
    if not base64_image:
        return jsonify({"error": "No image data received"}), 400

    saved_url = save_base64_image(base64_image, "test")
    if saved_url:
        return jsonify({"message": "Image saved successfully!", "url": saved_url}), 200
    else:
        return jsonify({"error": "Failed to save image"}), 500

# Function to process base64 images and store in MongoDB
def process_image(image, prefix):
    """Convert base64 image to a storable Base64 string or return the original value if it's a URL."""
    if not image:
        return None

    if image.startswith("data:image"):  # If Base64 image
        return save_base64_image(image, prefix)
    
    return image  # Assume it's an existing URL

@app.route('/has-attempted-quiz', methods=['POST'])
def has_attempted_quiz():
    try:
        data = request.json
        roll_no = data.get("roll_no")  # ✅ Use roll number instead of student name

        if not roll_no:
            return jsonify({"error": "Invalid request! Roll number is required."}), 400

        # 🔎 Check if this roll number has already taken the quiz
        existing_attempt = db["scores"].find_one({"roll_no": roll_no})

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
session
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

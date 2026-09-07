from flask import Flask, render_template, render_template_string, request, session, redirect, url_for, make_response
import os
import hashlib
import secrets
from datetime import datetime, timedelta
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Keep secrets outside source control. A random fallback keeps local development working.
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Session/cookie settings: secure cookies can be enabled on the deployed HTTPS site
# while local http://127.0.0.1 development continues to work.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
)

REMEMBER_COOKIE_NAME = "quiz_remember_token"
REMEMBER_DAYS = 30

# =========================================================
# POSTGRESQL CONFIGURATION
# =========================================================
# LOCAL: if DATABASE_URL is not set, the app uses PostgreSQL on localhost.
# RENDER: set DATABASE_URL to the Render PostgreSQL Internal Database URL.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
    "database": os.getenv("POSTGRES_DB", "online_quiz"),
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD", "")
}


def get_db_connection():
    if DATABASE_URL:
        # Render/cloud PostgreSQL connection.
        # The connection URL itself contains the required host/database/user credentials.
        return psycopg2.connect(DATABASE_URL)

    # Local PostgreSQL connection.
    return psycopg2.connect(**DB_CONFIG)


def ensure_base_tables():
    """Create the core PostgreSQL tables before any dependent tables."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                house VARCHAR(50),
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                subject VARCHAR(100) NOT NULL,
                difficulty VARCHAR(20) NOT NULL,
                question_text TEXT NOT NULL,
                option_a TEXT NOT NULL,
                option_b TEXT NOT NULL,
                option_c TEXT NOT NULL,
                option_d TEXT NOT NULL,
                correct_answer TEXT NOT NULL,
                explanation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quiz_results (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                subject VARCHAR(100) NOT NULL,
                difficulty VARCHAR(20) NOT NULL,
                score INTEGER NOT NULL DEFAULT 0,
                total_questions INTEGER NOT NULL DEFAULT 0,
                percentage NUMERIC(6,2) NOT NULL DEFAULT 0,
                completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS house VARCHAR(50)")
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE")
        cursor.execute("ALTER TABLE questions ADD COLUMN IF NOT EXISTS explanation TEXT")

        connection.commit()
        print("Base database tables are ready.")

    except Exception as e:
        if connection:
            connection.rollback()
        print("Base database setup error:", e)
        raise
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# Create core tables BEFORE any table that references users.
ensure_base_tables()


def ensure_remember_tokens_table():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remember_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(64) UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        print("Remember-token table setup error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def hash_remember_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_remember_token(user_id):
    token = secrets.token_urlsafe(48)
    token_hash = hash_remember_token(token)
    expires_at = datetime.utcnow() + timedelta(days=REMEMBER_DAYS)

    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM remember_tokens WHERE user_id = %s", (user_id,))
        cursor.execute(
            """
            INSERT INTO remember_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
            """,
            (user_id, token_hash, expires_at)
        )
        connection.commit()
        return token
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def clear_remember_token(token):
    if not token:
        return
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "DELETE FROM remember_tokens WHERE token_hash = %s",
            (hash_remember_token(token),)
        )
        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        print("Remember-token clear error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def restore_remembered_login():
    if session.get("user_id"):
        return

    token = request.cookies.get(REMEMBER_COOKIE_NAME)
    if not token:
        return

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT u.id, u.name, u.email, u.house
            FROM remember_tokens rt
            JOIN users u ON u.id = rt.user_id
            WHERE rt.token_hash = %s AND rt.expires_at > CURRENT_TIMESTAMP AND u.is_active = TRUE
            """,
            (hash_remember_token(token),)
        )
        user = cursor.fetchone()
        if user:
            user_id, name, email, house = user
            session["user_id"] = user_id
            session["user_name"] = name
            session["user_email"] = email
            session["user_house"] = house
        else:
            session.pop("user_id", None)
    except Exception as e:
        print("Remember-login restore error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def ensure_bookmarks_table():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bookmarks (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                question_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, question_id)
            )
        """)
        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        print("Bookmark table setup error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_bookmarked_question_ids(user_id):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT question_id FROM bookmarks WHERE user_id = %s",
            (user_id,)
        )
        return {row[0] for row in cursor.fetchall()}
    except Exception as e:
        print("Bookmark fetch error:", e)
        return set()
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def toggle_bookmark_in_db(user_id, question_id):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id FROM bookmarks WHERE user_id = %s AND question_id = %s",
            (user_id, question_id)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                "DELETE FROM bookmarks WHERE user_id = %s AND question_id = %s",
                (user_id, question_id)
            )
            action = "removed"
        else:
            cursor.execute(
                """
                INSERT INTO bookmarks (user_id, question_id)
                VALUES (%s, %s)
                ON CONFLICT (user_id, question_id) DO NOTHING
                """,
                (user_id, question_id)
            )
            action = "saved"

        connection.commit()
        return action
    except Exception:
        if connection:
            connection.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


ensure_remember_tokens_table()
ensure_bookmarks_table()


# =========================================================
# ADMIN AUTHENTICATION SYSTEM
# =========================================================

def ensure_admins_table():
    """Ensure the separate administrator account table exists."""
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.commit()

    except Exception as e:
        if connection:
            connection.rollback()
        print("Admin table setup error:", e)

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


ensure_admins_table()


@app.before_request
def auto_login_from_cookie():
    if request.endpoint not in {"static"}:
        restore_remembered_login()


def save_quiz_result(subject, difficulty, score, total_questions, percentage):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        '''
        INSERT INTO quiz_results
        (user_id, subject, difficulty, score, total_questions, percentage)
        VALUES (%s, %s, %s, %s, %s, %s)
        ''',
        (session.get("user_id"), subject, difficulty, score, total_questions, percentage)
    )

    connection.commit()
    cursor.close()
    connection.close()


def ensure_achievements_table():
    """Create the achievements table if it does not already exist."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS achievements (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                achievement_name VARCHAR(100) NOT NULL,
                description TEXT,
                earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, achievement_name)
            )
        """)
        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        print("Achievement table setup error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def award_achievement(user_id, achievement_name, description):
    """Award one achievement once per user."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO achievements (user_id, achievement_name, description)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id, achievement_name) DO NOTHING
            RETURNING id
            """,
            (user_id, achievement_name, description)
        )
        new_row = cursor.fetchone()
        connection.commit()
        return new_row is not None
    except Exception as e:
        if connection:
            connection.rollback()
        print("Achievement award error:", e)
        return False
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def evaluate_achievements(user_id, subject, score, total_questions, percentage):
    """Check milestone and performance achievements after a quiz attempt."""
    if not user_id:
        return []

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM quiz_results WHERE user_id = %s",
            (user_id,)
        )
        total_attempts = cursor.fetchone()[0] or 0

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM quiz_results
            WHERE user_id = %s AND subject = %s
            """,
            (user_id, subject)
        )
        subject_attempts = cursor.fetchone()[0] or 0

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM quiz_results
            WHERE user_id = %s AND percentage = 100
            """,
            (user_id,)
        )
        perfect_attempts = cursor.fetchone()[0] or 0

        cursor.execute(
            """
            SELECT COUNT(DISTINCT subject)
            FROM quiz_results
            WHERE user_id = %s
            """,
            (user_id,)
        )
        subjects_played = cursor.fetchone()[0] or 0

    except Exception as e:
        print("Achievement evaluation error:", e)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    rules = [
        (
            total_attempts >= 1,
            "Initiate",
            "Completed your first quiz and entered the learning journey."
        ),
        (
            total_attempts >= 3,
            "Knight",
            "Completed 3 quiz attempts and showed consistent progress."
        ),
        (
            total_attempts >= 5,
            "Elite",
            "Completed 5 quiz attempts and reached the Elite milestone."
        ),
        (
            total_attempts >= 10,
            "Champion",
            "Completed 10 quiz attempts and reached Champion level."
        ),
        (
            total_attempts >= 20,
            "Grandmaster",
            "Completed 20 quiz attempts and reached the highest core level."
        ),
        (
            percentage == 100,
            "Perfect Score",
            "Achieved a perfect score of 100% in a quiz."
        ),
        (
            subject_attempts >= 3,
            "Subject Expert",
            f"Completed 3 quizzes in {subject} and built strong subject experience."
        ),
        (
            subjects_played >= 4,
            "Quiz Explorer",
            "Completed quizzes across all 4 available subjects."
        ),
    ]

    unlocked = []
    for condition, name, description in rules:
        if condition and award_achievement(user_id, name, description):
            unlocked.append({
                "name": name,
                "description": description
            })

    return unlocked


def get_user_achievements(user_id):
    """Return earned achievements for the logged-in user."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT id, achievement_name, description, earned_at
            FROM achievements
            WHERE user_id = %s
            ORDER BY earned_at ASC, id ASC
            """,
            (user_id,)
        )
        rows = cursor.fetchall()
        return [
            {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "earned_at": row[3].strftime("%Y-%m-%d %H:%M:%S") if row[3] else ""
            }
            for row in rows
        ]
    except Exception as e:
        print("Achievement fetch error:", e)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


ensure_achievements_table()


# =========================================================
# CERTIFICATE STORAGE SYSTEM
# =========================================================

def ensure_certificates_table():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                certificate_type VARCHAR(100) NOT NULL,
                certificate_id VARCHAR(100) UNIQUE NOT NULL,
                title VARCHAR(200) NOT NULL,
                house_name VARCHAR(50),
                rank INTEGER,
                points INTEGER DEFAULT 0,
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("ALTER TABLE certificates ADD COLUMN IF NOT EXISTS certificate_type VARCHAR(100)")
        cursor.execute("ALTER TABLE certificates ADD COLUMN IF NOT EXISTS certificate_id VARCHAR(100)")
        cursor.execute("ALTER TABLE certificates ADD COLUMN IF NOT EXISTS title VARCHAR(200)")
        cursor.execute("ALTER TABLE certificates ADD COLUMN IF NOT EXISTS house_name VARCHAR(50)")
        cursor.execute("ALTER TABLE certificates ADD COLUMN IF NOT EXISTS rank INTEGER")
        cursor.execute("ALTER TABLE certificates ADD COLUMN IF NOT EXISTS points INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE certificates ADD COLUMN IF NOT EXISTS issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        print("Certificate table setup error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def save_house_certificate(user_id, house_name, rank, points):
    if not user_id or house_name not in HOUSE_NAMES:
        return None

    house_info = HOUSES[house_name]
    certificate_id = f"{house_info['short']}-EXCELLENCE-{int(user_id):06d}"
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO certificates (
                user_id, certificate_type, certificate_id, title,
                house_name, rank, points
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (certificate_id)
            DO UPDATE SET
                title = EXCLUDED.title,
                house_name = EXCLUDED.house_name,
                rank = EXCLUDED.rank,
                points = EXCLUDED.points
            RETURNING certificate_id, issued_at
        """, (
            user_id,
            "house_excellence",
            certificate_id,
            "Certificate of Excellence",
            house_name,
            rank,
            points
        ))
        row = cursor.fetchone()
        connection.commit()
        if row:
            return {"certificate_id": row[0], "issued_at": row[1]}
    except Exception as e:
        if connection:
            connection.rollback()
        print("House certificate save error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
    return None


def save_house_champion_certificate(user_id, champion_house, points):
    """Persist the House Champion certificate for a member of the winning House."""
    if not user_id or champion_house not in HOUSE_NAMES:
        return None

    house_info = HOUSES[champion_house]
    certificate_id = f"{house_info['short']}-CHAMPION-{int(user_id):06d}"
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO certificates (
                user_id, certificate_type, certificate_id, title,
                house_name, rank, points
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (certificate_id)
            DO UPDATE SET
                title = EXCLUDED.title,
                house_name = EXCLUDED.house_name,
                rank = EXCLUDED.rank,
                points = EXCLUDED.points
            RETURNING certificate_id, issued_at
        """, (
            user_id,
            "house_champion",
            certificate_id,
            "House Champion Certificate",
            champion_house,
            1,
            points
        ))

        row = cursor.fetchone()
        connection.commit()

        if row:
            return {"certificate_id": row[0], "issued_at": row[1]}

    except Exception as e:
        if connection:
            connection.rollback()
        print("House champion certificate save error:", e)

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return None


def award_champion_certificate_if_earned(user_id):
    """Automatically persist a Champion certificate when the student's House is #1."""
    if not user_id:
        return None

    try:
        student_house = get_user_house(user_id)
        if not student_house:
            return None

        all_time_house_totals = get_all_time_house_totals()
        if not all_time_house_totals:
            return None

        champion = all_time_house_totals[0]
        champion_house = champion.get("house")
        champion_points = champion.get("points", 0)

        if student_house != champion_house:
            return None

        return save_house_champion_certificate(
            user_id=user_id,
            champion_house=champion_house,
            points=champion_points
        )

    except Exception as e:
        print("Automatic Champion certificate error:", e)
        return None


# =========================================================
# STUDENT RANKING CERTIFICATES
# =========================================================

def save_student_rank_certificate(user_id, rank, points, house_name):
    """Persist an All-Time Student Ranking certificate for ranks 1, 2 or 3."""

    if not user_id or rank not in (1, 2, 3):
        return None

    if house_name not in HOUSE_NAMES:
        return None

    if int(points or 0) <= 0:
        return None

    rank_titles = {
        1: "Global Student Rank #1",
        2: "Global Student Rank #2",
        3: "Global Student Rank #3"
    }

    certificate_type = f"student_rank_{rank}"
    certificate_title = rank_titles[rank]
    certificate_id = f"STUDENT-RANK-{rank}-{int(user_id):06d}"

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO certificates (
                user_id, certificate_type, certificate_id, title,
                house_name, rank, points
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (certificate_id)
            DO NOTHING
            RETURNING certificate_id, issued_at
        """, (
            user_id,
            certificate_type,
            certificate_id,
            certificate_title,
            house_name,
            rank,
            points
        ))

        row = cursor.fetchone()
        connection.commit()

        if row:
            return {
                "certificate_id": row[0],
                "issued_at": row[1]
            }

        cursor.execute("""
            SELECT certificate_id, issued_at
            FROM certificates
            WHERE certificate_id = %s
              AND user_id = %s
        """, (certificate_id, user_id))

        existing = cursor.fetchone()

        if existing:
            return {
                "certificate_id": existing[0],
                "issued_at": existing[1]
            }

    except Exception as e:
        if connection:
            connection.rollback()
        print("Student rank certificate save error:", e)

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return None


def award_student_ranking_certificate_if_earned(user_id):
    """
    Automatically save a certificate when the student is currently
    ranked #1, #2 or #3 on the All-Time Student Leaderboard.
    """

    if not user_id:
        return None

    try:
        all_time_students = get_all_time_student_leaderboard()

        student = next(
            (
                item
                for item in all_time_students
                if item.get("user_id") == user_id
            ),
            None
        )

        if not student:
            return None

        rank = int(student.get("rank", 0))
        points = int(student.get("points", 0) or 0)
        house_name = student.get("house")

        if rank not in (1, 2, 3) or points <= 0:
            return None

        return save_student_rank_certificate(
            user_id=user_id,
            rank=rank,
            points=points,
            house_name=house_name
        )

    except Exception as e:
        print("Automatic Student Ranking certificate error:", e)
        return None


ensure_certificates_table()



# =========================================================
# QUIZ DATA
# 4 SUBJECTS x 3 DIFFICULTIES x 10 QUESTIONS
# =========================================================

quizzes = {

    "Science": {

        "Easy": [
            ("What is the chemical formula of water?",
             ["H2O", "CO2", "O2", "NaCl"], "H2O"),

            ("Which planet is called the Red Planet?",
             ["Earth", "Mars", "Venus", "Jupiter"], "Mars"),

            ("Which gas do humans need for breathing?",
             ["Oxygen", "Hydrogen", "Helium", "Carbon"], "Oxygen"),

            ("Which organ pumps blood?",
             ["Brain", "Heart", "Lungs", "Kidney"], "Heart"),

            ("What force pulls objects toward Earth?",
             ["Gravity", "Friction", "Heat", "Pressure"], "Gravity"),

            ("Which star is closest to Earth?",
             ["Sun", "Sirius", "Vega", "Polaris"], "Sun"),

            ("What is the boiling point of water?",
             ["50 C", "75 C", "100 C", "150 C"], "100 C"),

            ("Which part of a plant performs photosynthesis?",
             ["Root", "Leaf", "Seed", "Flower"], "Leaf"),

            ("Which organ is mainly used for breathing?",
             ["Heart", "Lungs", "Kidney", "Stomach"], "Lungs"),

            ("Which vitamin is produced with sunlight exposure?",
             ["Vitamin A", "Vitamin B", "Vitamin C", "Vitamin D"], "Vitamin D")
        ],

        "Medium": [
            ("What is the center of an atom called?",
             ["Nucleus", "Electron", "Proton", "Molecule"], "Nucleus"),

            ("Which particle has a negative charge?",
             ["Proton", "Neutron", "Electron", "Photon"], "Electron"),

            ("What is the basic unit of life?",
             ["Atom", "Cell", "Tissue", "Organ"], "Cell"),

            ("Which gas is most abundant in Earth's atmosphere?",
             ["Oxygen", "Nitrogen", "Hydrogen", "Carbon dioxide"], "Nitrogen"),

            ("What is the SI unit of force?",
             ["Joule", "Newton", "Watt", "Pascal"], "Newton"),

            ("Which blood cells fight infections?",
             ["Red blood cells", "White blood cells", "Platelets", "Plasma"],
             "White blood cells"),

            ("What process do plants use to make food?",
             ["Respiration", "Photosynthesis", "Digestion", "Fermentation"],
             "Photosynthesis"),

            ("Which organ filters waste from blood?",
             ["Heart", "Kidney", "Lung", "Brain"], "Kidney"),

            ("What is the chemical symbol for sodium?",
             ["So", "S", "Na", "Sd"], "Na"),

            ("Which planet has famous rings?",
             ["Mars", "Saturn", "Mercury", "Venus"], "Saturn")
        ],

        "Hard": [
            ("Newton's second law is expressed as?",
             ["F = ma", "E = mc2", "V = IR", "P = VI"], "F = ma"),

            ("What is known as the powerhouse of the cell?",
             ["Nucleus", "Ribosome", "Mitochondria", "Golgi body"],
             "Mitochondria"),

            ("Which particle determines atomic number?",
             ["Neutron", "Electron", "Proton", "Photon"], "Proton"),

            ("What is the pH of a neutral solution?",
             ["0", "5", "7", "14"], "7"),

            ("Which law relates pressure and volume at constant temperature?",
             ["Boyle's law", "Ohm's law", "Faraday's law", "Hooke's law"],
             "Boyle's law"),

            ("Which type of bond involves sharing electrons?",
             ["Ionic", "Covalent", "Metallic", "Nuclear"], "Covalent"),

            ("What is the SI unit of electric current?",
             ["Volt", "Ampere", "Ohm", "Watt"], "Ampere"),

            ("Which organelle contains genetic material in most cells?",
             ["Nucleus", "Lysosome", "Vacuole", "Ribosome"], "Nucleus"),

            ("What is acceleration measured in?",
             ["m/s", "m/s2", "kg/m", "N/m"], "m/s2"),

            ("Which phenomenon explains bending of light?",
             ["Reflection", "Refraction", "Diffusion", "Radiation"], "Refraction")
        ]
    },


    "Mathematics": {

        "Easy": [
            ("What is 15 + 27?", ["32", "42", "52", "62"], "42"),
            ("What is 12 x 8?", ["86", "96", "106", "116"], "96"),
            ("What is the square of 9?", ["18", "27", "81", "90"], "81"),
            ("What is 144 divided by 12?", ["10", "12", "14", "16"], "12"),
            ("What is 2 to the power 3?", ["6", "8", "9", "12"], "8"),
            ("What is 50 percent of 100?", ["25", "40", "50", "75"], "50"),
            ("How many sides does a triangle have?", ["2", "3", "4", "5"], "3"),
            ("What is 7 x 7?", ["42", "49", "56", "63"], "49"),
            ("What is 100 - 37?", ["53", "63", "73", "83"], "63"),
            ("What comes next: 2, 4, 6, 8?", ["9", "10", "11", "12"], "10")
        ],

        "Medium": [
            ("If x + 7 = 15, what is x?", ["6", "7", "8", "9"], "8"),
            ("Area of a rectangle with length 10 and width 5?",
             ["15", "30", "50", "100"], "50"),
            ("Average of 10, 20 and 30?",
             ["15", "20", "25", "30"], "20"),
            ("What comes next: 2, 4, 8, 16?",
             ["20", "24", "32", "36"], "32"),
            ("What is 25 percent of 200?",
             ["25", "40", "50", "75"], "50"),
            ("If 3x = 21, what is x?",
             ["5", "6", "7", "8"], "7"),
            ("Perimeter of a square with side 6?",
             ["12", "18", "24", "36"], "24"),
            ("What is 15 squared?",
             ["125", "200", "225", "250"], "225"),
            ("LCM of 4 and 6?",
             ["8", "10", "12", "24"], "12"),
            ("HCF of 18 and 24?",
             ["3", "6", "9", "12"], "6")
        ],

        "Hard": [
            ("Probability of getting heads on a fair coin?",
             ["0", "1/4", "1/2", "1"], "1/2"),

            ("If 2x + 5 = 17, what is x?",
             ["5", "6", "7", "8"], "6"),

            ("Derivative of x squared?",
             ["x", "2x", "x2", "2"], "2x"),

            ("What is the square root of 144?",
             ["10", "11", "12", "14"], "12"),

            ("Sum of first 10 positive integers?",
             ["45", "50", "55", "60"], "55"),

            ("If a:b = 2:3 and b = 12, what is a?",
             ["6", "8", "9", "10"], "8"),

            ("What is 5 factorial?",
             ["60", "100", "120", "150"], "120"),

            ("Slope of y = 3x + 2?",
             ["2", "3", "5", "1"], "3"),

            ("Determinant of [[1,2],[3,4]]?",
             ["-2", "2", "4", "10"], "-2"),

            ("What is log base 10 of 1000?",
             ["1", "2", "3", "10"], "3")
        ]
    },


    "Computer Science": {

        "Easy": [
            ("What does CPU stand for?",
             ["Central Processing Unit", "Computer Personal Unit",
              "Central Program Utility", "Control Processing Unit"],
             "Central Processing Unit"),

            ("What does RAM stand for?",
             ["Random Access Memory", "Read Access Memory",
              "Rapid Application Memory", "Run Access Module"],
             "Random Access Memory"),

            ("Which language is used to structure web pages?",
             ["HTML", "Python", "Java", "SQL"], "HTML"),

            ("Which symbol starts a comment in Python?",
             ["#", "//", "/*", "$"], "#"),

            ("Which device is used to type text?",
             ["Keyboard", "Monitor", "Speaker", "Printer"], "Keyboard"),

            ("Which one is an operating system?",
             ["Windows", "Chrome", "Google", "HTML"], "Windows"),

            ("What does URL stand for?",
             ["Uniform Resource Locator", "Universal Read Link",
              "User Resource Line", "Uniform Router Link"],
             "Uniform Resource Locator"),

            ("Which device displays computer output?",
             ["Monitor", "Keyboard", "Mouse", "Scanner"], "Monitor"),

            ("Which language is commonly used for data analysis?",
             ["Python", "HTML", "CSS", "XML"], "Python"),

            ("What is used to connect computers in a network?",
             ["Network", "Compiler", "Keyboard", "Printer"], "Network")
        ],

        "Medium": [
            ("Which data structure follows FIFO?",
             ["Stack", "Queue", "Tree", "Graph"], "Queue"),

            ("Which data structure follows LIFO?",
             ["Queue", "Stack", "Array", "Graph"], "Stack"),

            ("Which language is mainly used for database queries?",
             ["SQL", "HTML", "CSS", "Python"], "SQL"),

            ("What does OOP stand for?",
             ["Object Oriented Programming", "Online Operating Program",
              "Object Order Process", "Open Object Programming"],
             "Object Oriented Programming"),

            ("Which keyword creates a class in Python?",
             ["class", "object", "define", "new"], "class"),

            ("Which algorithm is used for shortest path?",
             ["Dijkstra", "Bubble Sort", "Binary Search", "DFS"],
             "Dijkstra"),

            ("What is the main purpose of an operating system?",
             ["Manage computer resources", "Create websites",
              "Edit photos", "Play only games"],
             "Manage computer resources"),

            ("Which is a relational database?",
             ["MySQL", "MongoDB", "Redis", "Neo4j"], "MySQL"),

            ("What does API stand for?",
             ["Application Programming Interface", "Application Process Input",
              "Advanced Program Internet", "Application Program Index"],
             "Application Programming Interface"),

            ("Which sorting algorithm repeatedly swaps adjacent elements?",
             ["Bubble Sort", "Merge Sort", "Quick Sort", "Heap Sort"],
             "Bubble Sort")
        ],

        "Hard": [
            ("Which data structure is commonly used in BFS?",
             ["Queue", "Stack", "Heap", "Array"], "Queue"),

            ("Which data structure is commonly used in DFS?",
             ["Stack", "Queue", "Heap", "Hash table"], "Stack"),

            ("Average time complexity of binary search?",
             ["O(n)", "O(log n)", "O(n2)", "O(1)"], "O(log n)"),

            ("Which normal form removes partial dependency?",
             ["1NF", "2NF", "3NF", "BCNF"], "2NF"),

            ("Which algorithm finds a minimum spanning tree?",
             ["Kruskal", "Binary Search", "DFS", "BFS"], "Kruskal"),

            ("Which algorithm is commonly used for minimum spanning tree?",
             ["Prim", "Dijkstra", "Binary Search", "Merge Sort"], "Prim"),

            ("What is a primary key used for?",
             ["Uniquely identify records", "Store images",
              "Delete tables", "Create passwords"],
             "Uniquely identify records"),

            ("Which protocol is commonly used for secure web browsing?",
             ["HTTPS", "FTP", "SMTP", "POP3"], "HTTPS"),

            ("What is recursion?",
             ["A function calling itself", "Sorting data",
              "Deleting memory", "Creating a database"],
             "A function calling itself"),

            ("Which memory is fastest among these?",
             ["Cache", "Hard Disk", "DVD", "USB Drive"], "Cache")
        ]
    },


    "Entertainment": {

        "Easy": [
            ("Which instrument has black and white keys?",
             ["Piano", "Guitar", "Flute", "Drums"], "Piano"),

            ("Which movie series features Hogwarts?",
             ["Harry Potter", "Avatar", "Rocky", "Toy Story"], "Harry Potter"),

            ("Which platform streams movies and shows?",
             ["Netflix", "Google Maps", "Calculator", "Paint"], "Netflix"),

            ("Which sport is played at Wimbledon?",
             ["Cricket", "Tennis", "Football", "Hockey"], "Tennis"),

            ("Who is known as the Dark Knight?",
             ["Batman", "Superman", "Thor", "Hulk"], "Batman"),

            ("Which character lives in a pineapple under the sea?",
             ["Shrek", "SpongeBob", "Tom", "Scooby-Doo"], "SpongeBob"),

            ("Which is mainly a music streaming service?",
             ["Spotify", "Google Maps", "Zoom", "Gmail"], "Spotify"),

            ("Which award is associated with cinema?",
             ["Oscar", "Grammy", "Nobel", "Emmy"], "Oscar"),

            ("Which superhero uses Mjolnir?",
             ["Thor", "Batman", "Flash", "Aquaman"], "Thor"),

            ("Which game is played with a bat and ball?",
             ["Cricket", "Swimming", "Boxing", "Chess"], "Cricket")
        ],

        "Medium": [
            ("What does CGI mean?",
             ["Computer Generated Imagery", "Cinema Graphics Interface",
              "Computer Game Integration", "Creative Graphic Illustration"],
             "Computer Generated Imagery"),

            ("Which genre commonly features futuristic technology?",
             ["Science Fiction", "Romance", "Western", "Comedy"],
             "Science Fiction"),

            ("Which instrument commonly has six strings?",
             ["Guitar", "Piano", "Trumpet", "Drum"], "Guitar"),

            ("Which award is mainly associated with music?",
             ["Grammy", "Oscar", "Nobel", "Booker"], "Grammy"),

            ("Which sport frequently uses the term hat-trick?",
             ["Football", "Swimming", "Golf", "Archery"], "Football"),

            ("What is a screenplay used for?",
             ["Planning a film", "Recording songs",
              "Editing photos", "Designing games"],
             "Planning a film"),

            ("Which device records professional audio?",
             ["Microphone", "Projector", "Keyboard", "Monitor"],
             "Microphone"),

            ("What does a director primarily do?",
             ["Guide creative production", "Sell tickets",
              "Write songs", "Operate cameras only"],
             "Guide creative production"),

            ("Which genre is intended to make audiences laugh?",
             ["Comedy", "Horror", "Thriller", "Documentary"], "Comedy"),

            ("What is a sequel?",
             ["Continuation of an earlier story", "Movie trailer",
              "Soundtrack", "Movie poster"],
             "Continuation of an earlier story")
        ],

        "Hard": [
            ("What is diegetic sound?",
             ["Sound originating within the story world",
              "Only background music", "Audience applause",
              "Sound added after release"],
             "Sound originating within the story world"),

            ("What does cinematography mainly concern?",
             ["Visual aspects of filmmaking", "Ticket pricing",
              "Music distribution", "Actor contracts"],
             "Visual aspects of filmmaking"),

            ("What is a montage?",
             ["A sequence of edited shots", "A microphone",
              "A cinema ticket", "A recording studio"],
             "A sequence of edited shots"),

            ("What is an ensemble cast?",
             ["Several major performers", "One actor only",
              "Only background actors", "A group of directors"],
             "Several major performers"),

            ("What is ADR in film production?",
             ["Automated Dialogue Replacement", "Advanced Digital Recording",
              "Audio Director Review", "Automatic Drama Rendering"],
             "Automated Dialogue Replacement"),

            ("What is a film score?",
             ["Original music written for a film", "Film rating",
              "Box-office total", "Movie script"],
             "Original music written for a film"),

            ("What does mise-en-scene refer to?",
             ["Elements arranged within a scene", "Ticket sales",
              "Film distribution", "Sound recording only"],
             "Elements arranged within a scene"),

            ("What is a plot twist?",
             ["Unexpected development in a story", "Camera lens",
              "Soundtrack", "Movie poster"],
             "Unexpected development in a story"),

            ("What is an adaptation?",
             ["A work transformed from another source",
              "Movie advertisement", "Cinema hall", "Sound effect"],
             "A work transformed from another source"),

            ("What does a film editor primarily control?",
             ["Arrangement and timing of shots", "Actor salaries",
              "Cinema seating", "Movie advertising"],
             "Arrangement and timing of shots")
        ]
    }
}




# =========================================================
# FOUR HOUSES — PREMIUM HOUSE SYSTEM
# =========================================================

HOUSES = {
    "Dravaryn": {
        "symbol": "🦁",
        "title": "The House of Valor",
        "motto": "Courage writes the legacy.",
        "identity": "Bold minds who lead with courage, discipline and determination.",
        "short": "VALOR"
    },
    "Aetherion": {
        "symbol": "🦅",
        "title": "The House of Vision",
        "motto": "Rise beyond the horizon.",
        "identity": "Visionaries who pursue knowledge, freedom and limitless possibility.",
        "short": "VISION"
    },
    "Valthera": {
        "symbol": "🐺",
        "title": "The House of Resolve",
        "motto": "Stand together. Stand unbroken.",
        "identity": "Strategic minds who value loyalty, resilience and quiet strength.",
        "short": "RESOLVE"
    },
    "Arcanis": {
        "symbol": "🐉",
        "title": "The House of Mastery",
        "motto": "Knowledge becomes power.",
        "identity": "Curious minds who seek mastery, creativity and deeper understanding.",
        "short": "MASTERY"
    }
}

HOUSE_NAMES = list(HOUSES.keys())
HOUSE_RANK_TITLES = {
    1: "House Sovereign",
    2: "High Vanguard",
    3: "Elite Vanguard"
}


def ensure_house_system():
    """Ensure the existing users table has House support and create point history."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS house VARCHAR(50)
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS house_point_events (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                house_name VARCHAR(50) NOT NULL,
                points INTEGER NOT NULL DEFAULT 0,
                subject VARCHAR(100),
                difficulty VARCHAR(20),
                score INTEGER,
                total_questions INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("ALTER TABLE house_point_events ADD COLUMN IF NOT EXISTS house_name VARCHAR(50)")
        cursor.execute("ALTER TABLE house_point_events ADD COLUMN IF NOT EXISTS points INTEGER NOT NULL DEFAULT 0")
        cursor.execute("ALTER TABLE house_point_events ADD COLUMN IF NOT EXISTS subject VARCHAR(100)")
        cursor.execute("ALTER TABLE house_point_events ADD COLUMN IF NOT EXISTS difficulty VARCHAR(20)")
        cursor.execute("ALTER TABLE house_point_events ADD COLUMN IF NOT EXISTS score INTEGER")
        cursor.execute("ALTER TABLE house_point_events ADD COLUMN IF NOT EXISTS total_questions INTEGER")
        cursor.execute("ALTER TABLE house_point_events ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_house_point_events_house
            ON house_point_events(house_name)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_house_point_events_user
            ON house_point_events(user_id)
        """)

        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        print("House system setup error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_user_house(user_id):
    """Return the currently assigned House for a user."""
    if not user_id:
        return None
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT house FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        return row[0] if row and row[0] in HOUSE_NAMES else None
    except Exception as e:
        print("House fetch error:", e)
        return None
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def set_user_house(user_id, house_name):
    """Assign a valid House to a user."""
    if house_name not in HOUSE_NAMES:
        return False
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE users SET house = %s WHERE id = %s",
            (house_name, user_id)
        )
        changed = cursor.rowcount > 0
        connection.commit()
        return changed
    except Exception as e:
        if connection:
            connection.rollback()
        print("House assignment error:", e)
        return False
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def calculate_house_points(difficulty, score, total_questions):
    """Calculate House points earned by one completed quiz."""
    multipliers = {
        "Easy": 10,
        "Medium": 15,
        "Hard": 20
    }
    multiplier = multipliers.get(difficulty, 10)
    points = max(0, int(score or 0)) * multiplier

    # Premium completion bonus for a perfect quiz.
    if total_questions and score == total_questions:
        points += 10

    return points


def award_house_points(user_id, house_name, subject, difficulty, score, total_questions):
    """Store an immutable House point event for all-time history."""
    if not user_id or house_name not in HOUSE_NAMES:
        return 0

    points = calculate_house_points(difficulty, score, total_questions)
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO house_point_events
            (user_id, house_name, points, subject, difficulty, score, total_questions)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            house_name,
            points,
            subject,
            difficulty,
            score,
            total_questions
        ))
        connection.commit()
        return points
    except Exception as e:
        if connection:
            connection.rollback()
        print("House point award error:", e)
        return 0
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_user_house_points(user_id):
    """Return the all-time points of the student's currently assigned House.

    House points belong to the House that earned them. They are not copied to
    another student and are not removed from a House when a student changes
    House later.
    """
    house_name = get_user_house(user_id)
    if not house_name:
        return 0

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT COALESCE(SUM(points), 0)
            FROM house_point_events
            WHERE house_name = %s
        """, (house_name,))
        return int(cursor.fetchone()[0] or 0)
    except Exception as e:
        print("House points error:", e)
        return 0
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_all_time_student_points(user_id):
    """Lifetime points earned by a student across every House."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT COALESCE(SUM(points), 0)
            FROM house_point_events
            WHERE user_id = %s
        """, (user_id,))
        return int(cursor.fetchone()[0] or 0)
    except Exception as e:
        print("All-time student points error:", e)
        return 0
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_current_house_leaderboard():
    """Rank students by points earned for their currently assigned House."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT
                u.id,
                u.name,
                u.house,
                COALESCE(SUM(hpe.points), 0) AS points
            FROM users u
            LEFT JOIN house_point_events hpe
                ON hpe.user_id = u.id
                AND hpe.house_name = u.house
            WHERE u.house IS NOT NULL
            GROUP BY u.id, u.name, u.house
            ORDER BY points DESC, u.name ASC
        """)
        rows = cursor.fetchall()

        result = []
        for index, row in enumerate(rows, start=1):
            rank = index
            result.append({
                "rank": rank,
                "user_id": row[0],
                "name": row[1],
                "house": row[2],
                "points": int(row[3] or 0),
                "rank_title": HOUSE_RANK_TITLES.get(rank, "House Contender")
            })
        return result
    except Exception as e:
        print("Current student leaderboard error:", e)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_all_time_student_leaderboard():
    """Rank students by lifetime House points."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT
                u.id,
                u.name,
                u.house,
                COALESCE(SUM(hpe.points), 0) AS points
            FROM users u
            LEFT JOIN house_point_events hpe ON hpe.user_id = u.id
            GROUP BY u.id, u.name, u.house
            ORDER BY points DESC, u.name ASC
        """)
        rows = cursor.fetchall()

        result = []
        for index, row in enumerate(rows, start=1):
            result.append({
                "rank": index,
                "user_id": row[0],
                "name": row[1],
                "house": row[2],
                "points": int(row[3] or 0),
                "rank_title": HOUSE_RANK_TITLES.get(index, "House Contender")
            })
        return result
    except Exception as e:
        print("All-time student leaderboard error:", e)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_current_house_leaderboard_by_house(house_name):
    """Current ranking inside one House using the student's current House."""
    if house_name not in HOUSE_NAMES:
        return []

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT
                u.id,
                u.name,
                COALESCE(SUM(hpe.points), 0) AS points
            FROM users u
            LEFT JOIN house_point_events hpe
                ON hpe.user_id = u.id
                AND hpe.house_name = u.house
            WHERE u.house = %s
            GROUP BY u.id, u.name
            ORDER BY points DESC, u.name ASC
        """, (house_name,))
        rows = cursor.fetchall()

        result = []
        for index, row in enumerate(rows, start=1):
            result.append({
                "rank": index,
                "user_id": row[0],
                "name": row[1],
                "points": int(row[2] or 0),
                "rank_title": HOUSE_RANK_TITLES.get(index, "House Contender")
            })
        return result
    except Exception as e:
        print("House ranking error:", e)
        return []
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


class HouseTotalsCollection(list):
    """List of House totals that also supports dictionary-style .get()."""

    def get(self, house_name, default=None):
        for item in self:
            if isinstance(item, dict) and item.get("house") == house_name:
                return item
        return default


def get_current_house_totals():
    """Return live House standings for all four Houses.

    Each quiz point event belongs to exactly one House. Every student's points
    contribute to that House total, while each student's personal total remains
    separate in the student leaderboard.
    """
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT h.house_name,
                   COALESCE(SUM(hpe.points), 0) AS total_points,
                   COUNT(DISTINCT u.id) AS members
            FROM (
                SELECT UNNEST(%s::varchar[]) AS house_name
            ) h
            LEFT JOIN house_point_events hpe
                ON hpe.house_name = h.house_name
            LEFT JOIN users u
                ON u.id = hpe.user_id
               AND u.house = h.house_name
            GROUP BY h.house_name
            ORDER BY total_points DESC, h.house_name ASC
        """, (HOUSE_NAMES,))
        rows = cursor.fetchall()

        result = HouseTotalsCollection([
            {
                "house": row[0],
                "points": int(row[1] or 0),
                "members": int(row[2] or 0)
            }
            for row in rows
        ])

        existing = {item["house"] for item in result}
        for house_name in HOUSE_NAMES:
            if house_name not in existing:
                result.append({"house": house_name, "points": 0, "members": 0})

        result.sort(key=lambda item: (-int(item.get("points", 0)), item.get("house", "")))
        return result

    except Exception as e:
        print("Current House totals error:", e)
        return HouseTotalsCollection([
            {"house": name, "points": 0, "members": 0}
            for name in HOUSE_NAMES
        ])
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


def get_all_time_house_totals():
    """Return lifetime points for every House, including Houses at zero."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT h.house_name,
                   COALESCE(SUM(hpe.points), 0) AS total_points
            FROM (
                SELECT UNNEST(%s::varchar[]) AS house_name
            ) h
            LEFT JOIN house_point_events hpe
                ON hpe.house_name = h.house_name
            GROUP BY h.house_name
            ORDER BY total_points DESC, h.house_name ASC
        """, (HOUSE_NAMES,))
        rows = cursor.fetchall()

        result = HouseTotalsCollection([
            {"house": row[0], "points": int(row[1] or 0)}
            for row in rows
        ])

        existing = {item["house"] for item in result}
        for house_name in HOUSE_NAMES:
            if house_name not in existing:
                result.append({"house": house_name, "points": 0})

        result.sort(key=lambda item: (-int(item.get("points", 0)), item.get("house", "")))
        return result
    except Exception as e:
        print("All-time House totals error:", e)
        return HouseTotalsCollection([{"house": name, "points": 0} for name in HOUSE_NAMES])
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


ensure_house_system()


# =========================================================
# ADMIN LOGIN — OWNER ONLY
# =========================================================

# This is the ONLY email allowed to authenticate through the
# Admin Login. Student authentication remains completely separate.
OWNER_ADMIN_EMAIL = os.getenv("OWNER_ADMIN_EMAIL", "raj792negi@gmail.com").strip()


def admin_required():
    """Protect Admin routes with the owner-only administrator session."""
    if not session.get("admin_id"):
        return redirect(url_for("admin_login"))
    return None


def ensure_admin_question_fields():
    """Add the editable explanation field to the PostgreSQL question bank."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("ALTER TABLE questions ADD COLUMN IF NOT EXISTS explanation TEXT")
        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        print("Admin question fields setup error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()



ensure_admin_question_fields()

def sync_quizzes_from_db():
    """Use PostgreSQL questions as the live quiz source after admin changes."""
    global quizzes
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT subject, difficulty, question_text,
                   option_a, option_b, option_c, option_d, correct_answer
            FROM questions
            ORDER BY id ASC
        """)
        rows = cursor.fetchall()
        if not rows:
            print("Question bank sync skipped: questions table is empty.")
            return False

        synced = {}
        for row in rows:
            subject, difficulty, question_text, option_a, option_b, option_c, option_d, correct_answer = row
            synced.setdefault(subject, {}).setdefault(difficulty, []).append((
                question_text,
                [option_a, option_b, option_c, option_d],
                correct_answer
            ))

        quizzes = synced
        total = sum(len(items) for difficulty_data in quizzes.values() for items in difficulty_data.values())
        print("Question bank synced from PostgreSQL:", total, "questions")
        return True
    except Exception as e:
        print("Question bank sync error:", e)
        return False
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()




@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    """Secure administrator login restricted to the owner's email."""

    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    error = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            error = "Please enter your admin email and password."

        # --------------------------------------------------------
        # OWNER-ONLY SECURITY CHECK
        # --------------------------------------------------------
        elif email != OWNER_ADMIN_EMAIL.lower():
            error = "Invalid admin email or password."

        else:
            connection = None
            cursor = None

            try:
                connection = get_db_connection()
                cursor = connection.cursor()

                # Always fetch ONLY the owner admin record.
                cursor.execute("""
                    SELECT id, name, email, password
                    FROM admins
                    WHERE LOWER(email) = %s
                    LIMIT 1
                """, (OWNER_ADMIN_EMAIL.lower(),))

                admin = cursor.fetchone()

                if admin and check_password_hash(admin[3], password):
                    # Clear any student authentication before creating
                    # the administrator session.
                    session.pop("user_id", None)
                    session.pop("user_name", None)
                    session.pop("user_email", None)
                    session.pop("user_house", None)

                    session["admin_id"] = admin[0]
                    session["admin_name"] = admin[1]
                    session["admin_email"] = admin[2]

                    return redirect(url_for("admin_dashboard"))

                error = "Invalid admin email or password."

            except Exception as e:
                print("Admin login database error:", e)
                error = "Unable to login right now. Please try again."

            finally:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()

    return render_template("admin_login.html", error=error)


# =========================================================
# ADMIN QUESTION BANK — FULL CRUD
# =========================================================

@app.route("/admin/questions")
def admin_questions():
    """Owner-only question bank management page."""
    guard = admin_required()
    if guard:
        return guard

    search_query = request.args.get("search", "").strip()
    selected_subject = request.args.get("subject", "All")
    selected_difficulty = request.args.get("difficulty", "All")

    connection = None
    cursor = None
    questions = []
    subjects = []
    difficulties = ["Easy", "Medium", "Hard"]
    total_questions = 0

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        conditions = []
        params = []

        if selected_subject != "All":
            conditions.append("subject = %s")
            params.append(selected_subject)

        if selected_difficulty != "All":
            conditions.append("difficulty = %s")
            params.append(selected_difficulty)

        if search_query:
            conditions.append("""(question_text ILIKE %s OR option_a ILIKE %s
                OR option_b ILIKE %s OR option_c ILIKE %s
                OR option_d ILIKE %s OR correct_answer ILIKE %s)""")
            search_value = f"%{search_query}%"
            params.extend([search_value] * 6)

        where_sql = "WHERE " + " AND ".join(conditions) if conditions else ""

        cursor.execute(f"""
            SELECT id, subject, difficulty, question_text,
                   option_a, option_b, option_c, option_d,
                   correct_answer, COALESCE(explanation, '')
            FROM questions
            {where_sql}
            ORDER BY id ASC
        """, tuple(params))

        rows = cursor.fetchall()
        questions = [
            {
                "id": row[0], "subject": row[1], "difficulty": row[2],
                "question_text": row[3], "option_a": row[4], "option_b": row[5],
                "option_c": row[6], "option_d": row[7],
                "correct_answer": row[8], "explanation": row[9]
            }
            for row in rows
        ]

        cursor.execute("SELECT DISTINCT subject FROM questions ORDER BY subject")
        subjects = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT COUNT(*) FROM questions")
        total_questions = int(cursor.fetchone()[0] or 0)

    except Exception as e:
        print("Admin question bank error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template(
        "admin_questions.html",
        admin_name=session.get("admin_name", "Administrator"),
        questions=questions, subjects=subjects, difficulties=difficulties,
        selected_subject=selected_subject, selected_difficulty=selected_difficulty,
        search_query=search_query, total_questions=total_questions
    )


@app.route("/admin/questions/add", methods=["GET", "POST"])
def admin_add_question():
    guard = admin_required()
    if guard:
        return guard
    subjects = ["Science", "Mathematics", "Computer Science", "Entertainment"]
    difficulties = ["Easy", "Medium", "Hard"]
    if request.method == "GET":
        return render_template("admin_question_form.html", admin_name=session.get("admin_name","Administrator"), mode="add", question=None, subjects=subjects, difficulties=difficulties, error=None)
    question, errors = _admin_clean_question_form()
    if errors:
        return render_template("admin_question_form.html", admin_name=session.get("admin_name","Administrator"), mode="add", question=question, subjects=subjects, difficulties=difficulties, error=" ".join(errors))
    connection=None; cursor=None
    try:
        connection=get_db_connection(); cursor=connection.cursor()
        cursor.execute("""INSERT INTO questions (subject,difficulty,question_text,option_a,option_b,option_c,option_d,correct_answer,explanation) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (question["subject"],question["difficulty"],question["question_text"],question["option_a"],question["option_b"],question["option_c"],question["option_d"],question["correct_answer"],question["explanation"]))
        connection.commit(); sync_quizzes_from_db(); return redirect(url_for("admin_questions"))
    except Exception as e:
        if connection: connection.rollback()
        print("Admin add question error:",e)
        return render_template("admin_question_form.html", admin_name=session.get("admin_name","Administrator"), mode="add", question=question, subjects=subjects, difficulties=difficulties, error="Unable to add the question right now.")
    finally:
        if cursor: cursor.close()
        if connection: connection.close()


@app.route("/admin/questions/edit/<int:question_id>", methods=["GET", "POST"])
def admin_edit_question(question_id):
    guard=admin_required()
    if guard: return guard
    subjects=["Science","Mathematics","Computer Science","Entertainment"]
    difficulties=["Easy","Medium","Hard"]
    connection=None; cursor=None
    try:
        connection=get_db_connection(); cursor=connection.cursor()
        if request.method=="GET":
            cursor.execute("SELECT id,subject,difficulty,question_text,option_a,option_b,option_c,option_d,correct_answer,COALESCE(explanation,'') FROM questions WHERE id=%s",(question_id,))
            r=cursor.fetchone()
            if not r: return redirect(url_for("admin_questions"))
            question={"id":r[0],"subject":r[1],"difficulty":r[2],"question_text":r[3],"option_a":r[4],"option_b":r[5],"option_c":r[6],"option_d":r[7],"correct_answer":r[8],"explanation":r[9]}
            return render_template("admin_question_form.html",admin_name=session.get("admin_name","Administrator"),mode="edit",question=question,subjects=subjects,difficulties=difficulties,error=None)
        question, errors=_admin_clean_question_form(); question["id"]=question_id
        if errors:
            return render_template("admin_question_form.html",admin_name=session.get("admin_name","Administrator"),mode="edit",question=question,subjects=subjects,difficulties=difficulties,error=" ".join(errors))
        cursor.execute("""UPDATE questions SET subject=%s,difficulty=%s,question_text=%s,option_a=%s,option_b=%s,option_c=%s,option_d=%s,correct_answer=%s,explanation=%s WHERE id=%s""",(question["subject"],question["difficulty"],question["question_text"],question["option_a"],question["option_b"],question["option_c"],question["option_d"],question["correct_answer"],question["explanation"],question_id))
        connection.commit(); sync_quizzes_from_db(); return redirect(url_for("admin_questions"))
    except Exception as e:
        if connection: connection.rollback()
        print("Admin edit question error:",e)
        return redirect(url_for("admin_questions"))
    finally:
        if cursor: cursor.close()
        if connection: connection.close()


@app.route("/admin/questions/delete/<int:question_id>", methods=["POST"])
def admin_delete_question(question_id):
    """Delete a question and immediately refresh the live quiz bank."""
    guard = admin_required()
    if guard:
        return guard

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("DELETE FROM questions WHERE id = %s", (question_id,))
        connection.commit()
        sync_quizzes_from_db()
    except Exception as e:
        if connection:
            connection.rollback()
        print("Admin delete question error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect(url_for("admin_questions"))


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin-dashboard")
def admin_dashboard():
    """Administrator dashboard with live PostgreSQL statistics."""
    if not session.get("admin_id"):
        return redirect(url_for("admin_login"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Student statistics
        cursor.execute("SELECT COUNT(*) FROM users")
        total_students = int(cursor.fetchone()[0] or 0)

        cursor.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE house IS NOT NULL
        """)
        students_with_house = int(cursor.fetchone()[0] or 0)

        # Quiz statistics
        cursor.execute("SELECT COUNT(*) FROM quiz_results")
        total_quizzes = int(cursor.fetchone()[0] or 0)

        cursor.execute("""
            SELECT COALESCE(SUM(score), 0),
                   COALESCE(SUM(total_questions), 0),
                   COALESCE(AVG(percentage), 0)
            FROM quiz_results
        """)
        quiz_stats = cursor.fetchone()
        total_correct = int(quiz_stats[0] or 0)
        total_questions = int(quiz_stats[1] or 0)
        average_percentage = float(quiz_stats[2] or 0)

        # Bookmark and achievement statistics
        cursor.execute("SELECT COUNT(*) FROM bookmarks")
        total_bookmarks = int(cursor.fetchone()[0] or 0)

        cursor.execute("SELECT COUNT(*) FROM achievements")
        total_achievements = int(cursor.fetchone()[0] or 0)

        # Certificate statistics
        cursor.execute("SELECT COUNT(*) FROM certificates")
        total_certificates = int(cursor.fetchone()[0] or 0)

        # House point statistics
        cursor.execute("""
            SELECT
                house_name,
                COALESCE(SUM(points), 0) AS points
            FROM house_point_events
            GROUP BY house_name
            ORDER BY points DESC, house_name ASC
        """)
        house_rows = cursor.fetchall()

        house_totals = [
            {
                "house": row[0],
                "points": int(row[1] or 0)
            }
            for row in house_rows
        ]

        # Recent quiz activity
        cursor.execute("""
            SELECT
                qr.id,
                u.name,
                qr.subject,
                qr.difficulty,
                qr.score,
                qr.total_questions,
                qr.percentage,
                qr.completed_at
            FROM quiz_results qr
            JOIN users u ON u.id = qr.user_id
            ORDER BY qr.completed_at DESC, qr.id DESC
            LIMIT 10
        """)
        recent_rows = cursor.fetchall()

        recent_quizzes = [
            {
                "id": row[0],
                "student_name": row[1],
                "subject": row[2],
                "difficulty": row[3],
                "score": row[4],
                "total_questions": row[5],
                "percentage": float(row[6] or 0),
                "completed_at": row[7]
            }
            for row in recent_rows
        ]

        return render_template(
            "admin_dashboard.html",
            admin_name=session.get("admin_name", "Administrator"),
            total_students=total_students,
            students_with_house=students_with_house,
            total_quizzes=total_quizzes,
            total_correct=total_correct,
            total_questions=total_questions,
            average_percentage=round(average_percentage, 2),
            total_bookmarks=total_bookmarks,
            total_achievements=total_achievements,
            total_certificates=total_certificates,
            house_totals=house_totals,
            recent_quizzes=recent_quizzes
        )

    except Exception as e:
        print("Admin dashboard database error:", e)
        return render_template(
            "admin_dashboard.html",
            admin_name=session.get("admin_name", "Administrator"),
            total_students=0,
            students_with_house=0,
            total_quizzes=0,
            total_correct=0,
            total_questions=0,
            average_percentage=0,
            total_bookmarks=0,
            total_achievements=0,
            total_certificates=0,
            house_totals=[],
            recent_quizzes=[],
            error="Unable to load some dashboard data."
        )

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# ADMIN LOGOUT
# =========================================================

@app.route("/admin-logout")
def admin_logout():
    """Log out the administrator without affecting the database."""
    session.pop("admin_id", None)
    session.pop("admin_name", None)
    session.pop("admin_email", None)
    return redirect(url_for("admin_login"))



# =========================================================
# COMPLETE ADMIN CONTROL CENTER — OWNER ONLY
# =========================================================

def ensure_admin_system_fields():
    """Add safe fields needed by the Admin Control Center."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE")
        cursor.execute("ALTER TABLE questions ADD COLUMN IF NOT EXISTS explanation TEXT")
        cursor.execute("UPDATE users SET is_active = TRUE WHERE is_active IS NULL")
        connection.commit()
    except Exception as e:
        if connection:
            connection.rollback()
        print("Admin system fields setup error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


ensure_admin_system_fields()


def _admin_fetchone(sql, params=()):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(sql, params)
        return cursor.fetchone()
    finally:
        cursor.close()
        connection.close()


def _admin_fetchall(sql, params=()):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(sql, params)
        return cursor.fetchall()
    finally:
        cursor.close()
        connection.close()


def _admin_clean_question_form():
    """Read and validate question form data. Correct answer is selected by option key."""
    subject = request.form.get("subject", "").strip()
    difficulty = request.form.get("difficulty", "").strip()
    question_text = request.form.get("question_text", "").strip()
    options = [
        request.form.get("option_a", "").strip(),
        request.form.get("option_b", "").strip(),
        request.form.get("option_c", "").strip(),
        request.form.get("option_d", "").strip(),
    ]
    correct_key = request.form.get("correct_key", "").strip().upper()
    # Backward compatibility with an older form that posted the answer text.
    legacy_correct = request.form.get("correct_answer", "").strip()
    explanation = request.form.get("explanation", "").strip()

    subjects = ["Science", "Mathematics", "Computer Science", "Entertainment"]
    difficulties = ["Easy", "Medium", "Hard"]
    errors = []

    if subject not in subjects:
        errors.append("Please choose a valid subject.")
    if difficulty not in difficulties:
        errors.append("Please choose a valid difficulty.")
    if not question_text:
        errors.append("Question text is required.")
    if any(not option for option in options):
        errors.append("All four options are required.")

    normalized_options = [option.casefold() for option in options if option]
    if len(normalized_options) == 4 and len(set(normalized_options)) != 4:
        errors.append("All four options must be different.")

    if correct_key not in {"A", "B", "C", "D"}:
        if legacy_correct and legacy_correct in options:
            correct_key = "ABCD"[options.index(legacy_correct)]
        else:
            errors.append("Please select the correct option.")

    correct_answer = options["ABCD".index(correct_key)] if correct_key in "ABCD" and options["ABCD".index(correct_key)] else ""

    return {
        "subject": subject,
        "difficulty": difficulty,
        "question_text": question_text,
        "option_a": options[0],
        "option_b": options[1],
        "option_c": options[2],
        "option_d": options[3],
        "correct_answer": correct_answer,
        "correct_key": correct_key,
        "explanation": explanation,
    }, errors


@app.route("/admin/students")
def admin_students():
    guard = admin_required()
    if guard:
        return guard

    search = request.args.get("search", "").strip()
    selected_house = request.args.get("house", "All")
    status = request.args.get("status", "All")
    houses = HOUSE_NAMES
    students = []
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        conditions = []
        params = []
        if search:
            conditions.append("(u.name ILIKE %s OR u.email ILIKE %s)")
            value = f"%{search}%"
            params.extend([value, value])
        if selected_house in houses:
            conditions.append("u.house = %s")
            params.append(selected_house)
        if status == "Active":
            conditions.append("u.is_active = TRUE")
        elif status == "Inactive":
            conditions.append("u.is_active = FALSE")
        where_sql = "WHERE " + " AND ".join(conditions) if conditions else ""
        cursor.execute(f"""
            SELECT u.id, u.name, u.email, u.house, u.is_active,
                   COUNT(DISTINCT qr.id) AS attempts,
                   COALESCE(ROUND(AVG(qr.percentage)::numeric, 2), 0) AS avg_percentage,
                   COALESCE((SELECT SUM(hpe.points) FROM house_point_events hpe WHERE hpe.user_id=u.id),0) AS points,
                   (SELECT COUNT(*) FROM achievements a WHERE a.user_id=u.id) AS achievements,
                   (SELECT COUNT(*) FROM certificates c WHERE c.user_id=u.id) AS certificates,
                   (SELECT COUNT(*) FROM bookmarks b WHERE b.user_id=u.id) AS bookmarks
            FROM users u
            LEFT JOIN quiz_results qr ON qr.user_id=u.id
            {where_sql}
            GROUP BY u.id, u.name, u.email, u.house, u.is_active
            ORDER BY u.id DESC
        """, tuple(params))
        rows = cursor.fetchall()
        students = [{
            "id": r[0], "name": r[1], "email": r[2], "house": r[3], "is_active": bool(r[4]),
            "attempts": int(r[5] or 0), "avg_percentage": float(r[6] or 0), "points": int(r[7] or 0),
            "achievements": int(r[8] or 0), "certificates": int(r[9] or 0), "bookmarks": int(r[10] or 0)
        } for r in rows]
    except Exception as e:
        print("Admin students error:", e)
    finally:
        if cursor: cursor.close()
        if connection: connection.close()

    return render_template("admin_students.html", admin_name=session.get("admin_name", "Administrator"),
                           students=students, houses=houses, search=search,
                           selected_house=selected_house, status=status)


@app.route("/admin/students/view/<int:user_id>")
def admin_student_view(user_id):
    guard = admin_required()
    if guard: return guard
    connection = None
    cursor = None
    try:
        connection = get_db_connection(); cursor = connection.cursor()
        cursor.execute("SELECT id,name,email,house,is_active,created_at FROM users WHERE id=%s", (user_id,))
        r = cursor.fetchone()
        if not r: return redirect(url_for("admin_students"))
        cursor.execute("SELECT subject,difficulty,score,total_questions,percentage,completed_at,id FROM quiz_results WHERE user_id=%s ORDER BY completed_at DESC,id DESC", (user_id,))
        quizzes_rows = cursor.fetchall()
        cursor.execute("SELECT id,achievement_name,description,earned_at FROM achievements WHERE user_id=%s ORDER BY earned_at DESC,id DESC", (user_id,))
        ach_rows = cursor.fetchall()
        cursor.execute("SELECT id,certificate_id,title,issued_at,house_name,rank,points FROM certificates WHERE user_id=%s ORDER BY issued_at DESC,id DESC", (user_id,))
        cert_rows = cursor.fetchall()
        cursor.execute("""SELECT b.id,b.question_id,q.question_text FROM bookmarks b LEFT JOIN questions q ON q.id=b.question_id WHERE b.user_id=%s ORDER BY b.created_at DESC,b.id DESC""", (user_id,))
        book_rows = cursor.fetchall()
        cursor.execute("SELECT house_name,points,subject,difficulty,score,total_questions,created_at FROM house_point_events WHERE user_id=%s ORDER BY created_at DESC,id DESC", (user_id,))
        point_rows = cursor.fetchall()
        cursor.execute("SELECT COALESCE(SUM(points),0) FROM house_point_events WHERE user_id=%s", (user_id,))
        lifetime = int(cursor.fetchone()[0] or 0)
        student = {"id":r[0],"name":r[1],"email":r[2],"house":r[3],"is_active":bool(r[4]),"created_at":r[5]}
        quizzes = [{"subject":x[0],"difficulty":x[1],"score":x[2],"total":x[3],"percentage":float(x[4] or 0),"completed_at":x[5],"id":x[6]} for x in quizzes_rows]
        achievements = [{"id":x[0],"name":x[1],"description":x[2],"earned_at":x[3]} for x in ach_rows]
        certificates = [{"id":x[0],"certificate_id":x[1],"title":x[2],"issued_at":x[3],"house":x[4],"rank":x[5],"points":x[6]} for x in cert_rows]
        bookmarks = [{"id":x[0],"question_id":x[1],"question_text":x[2]} for x in book_rows]
        points_history = [{"house":x[0],"points":x[1],"subject":x[2],"difficulty":x[3],"score":x[4],"total":x[5],"created_at":x[6]} for x in point_rows]
        student["all_time_points"] = lifetime
        return render_template("admin_student_view.html", admin_name=session.get("admin_name","Administrator"), student=student,
                               houses=HOUSE_NAMES, quizzes=quizzes, achievements=achievements,
                               certificates=certificates, bookmarks=bookmarks, points_history=points_history)
    except Exception as e:
        print("Admin student view error:", e); return redirect(url_for("admin_students"))
    finally:
        if cursor: cursor.close()
        if connection: connection.close()


@app.route("/admin/students/edit/<int:user_id>", methods=["GET","POST"])
def admin_edit_student(user_id):
    guard = admin_required()
    if guard: return guard
    error = None
    connection = None; cursor = None
    try:
        connection = get_db_connection(); cursor = connection.cursor()
        if request.method == "GET":
            cursor.execute("SELECT id,name,email,house,is_active FROM users WHERE id=%s", (user_id,))
            r = cursor.fetchone()
            if not r: return redirect(url_for("admin_students"))
            student={"id":r[0],"name":r[1],"email":r[2],"house":r[3],"is_active":bool(r[4])}
            return render_template("admin_student_form.html", admin_name=session.get("admin_name","Administrator"), student=student, houses=HOUSE_NAMES, error=None)
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower(); house=request.form.get("house","").strip() or None; is_active=request.form.get("is_active")=="on"
        if not name or not email: error="Name and email are required."
        elif len(name)>100: error="Name must be 100 characters or fewer."
        elif len(email)>150: error="Email must be 150 characters or fewer."
        elif house and house not in HOUSE_NAMES: error="Invalid House selected."
        else:
            cursor.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(%s) AND id<>%s", (email,user_id))
            if cursor.fetchone(): error="That email is already used by another student."
        student={"id":user_id,"name":name,"email":email,"house":house,"is_active":is_active}
        if error:
            return render_template("admin_student_form.html", admin_name=session.get("admin_name","Administrator"), student=student, houses=HOUSE_NAMES, error=error)
        cursor.execute("UPDATE users SET name=%s,email=%s,house=%s,is_active=%s WHERE id=%s", (name,email,house,is_active,user_id))
        connection.commit()
        return redirect(url_for("admin_student_view",user_id=user_id))
    except Exception as e:
        if connection: connection.rollback()
        print("Admin edit student error:",e)
        return render_template("admin_student_form.html", admin_name=session.get("admin_name","Administrator"), student=locals().get("student",{"id":user_id,"name":"","email":"","house":None,"is_active":True}), houses=HOUSE_NAMES, error="Unable to save student.")
    finally:
        if cursor: cursor.close()
        if connection: connection.close()


@app.route("/admin/students/change-house/<int:user_id>", methods=["POST"])
def admin_change_student_house(user_id):
    guard=admin_required()
    if guard:return guard
    house=request.form.get("house","").strip()
    if house in HOUSE_NAMES: set_user_house(user_id,house)
    return redirect(url_for("admin_student_view",user_id=user_id))


@app.route("/admin/students/toggle/<int:user_id>", methods=["POST"])
def admin_toggle_student(user_id):
    guard=admin_required()
    if guard:return guard
    connection=None; cursor=None
    try:
        connection=get_db_connection(); cursor=connection.cursor()
        cursor.execute("UPDATE users SET is_active=NOT is_active WHERE id=%s",(user_id,)); connection.commit()
    except Exception as e:
        if connection: connection.rollback()
        print("Admin toggle student error:",e)
    finally:
        if cursor: cursor.close()
        if connection: connection.close()
    return redirect(url_for("admin_student_view",user_id=user_id))


@app.route("/admin/students/delete/<int:user_id>", methods=["POST"])
def admin_delete_student(user_id):
    guard=admin_required()
    if guard:return guard
    connection=None; cursor=None
    try:
        connection=get_db_connection(); cursor=connection.cursor()
        cursor.execute("DELETE FROM users WHERE id=%s",(user_id,)); connection.commit()
    except Exception as e:
        if connection: connection.rollback()
        print("Admin delete student error:",e)
    finally:
        if cursor: cursor.close()
        if connection: connection.close()
    return redirect(url_for("admin_students"))


@app.route("/admin/quiz-history")
def admin_quiz_history():
    guard=admin_required()
    if guard:return guard
    search=request.args.get("search","").strip(); subject=request.args.get("subject","All"); difficulty=request.args.get("difficulty","All")
    conditions=[]; params=[]
    if search: conditions.append("(u.name ILIKE %s OR u.email ILIKE %s)"); v=f"%{search}%"; params += [v,v]
    if subject!="All": conditions.append("qr.subject=%s"); params.append(subject)
    if difficulty!="All": conditions.append("qr.difficulty=%s"); params.append(difficulty)
    where="WHERE "+" AND ".join(conditions) if conditions else ""
    rows=_admin_fetchall(f"""SELECT qr.id,u.name,u.email,qr.subject,qr.difficulty,qr.score,qr.total_questions,qr.percentage,qr.completed_at,u.house FROM quiz_results qr JOIN users u ON u.id=qr.user_id {where} ORDER BY qr.completed_at DESC,qr.id DESC""",tuple(params))
    results=[{"id":r[0],"name":r[1],"email":r[2],"subject":r[3],"difficulty":r[4],"score":r[5],"total":r[6],"percentage":float(r[7] or 0),"completed_at":r[8],"house":r[9]} for r in rows]
    subjects=[r[0] for r in _admin_fetchall("SELECT DISTINCT subject FROM quiz_results ORDER BY subject")]
    return render_template("admin_quiz_history.html",admin_name=session.get("admin_name","Administrator"),results=results,search=search,subjects=subjects,difficulties=["Easy","Medium","Hard"],selected_subject=subject,selected_difficulty=difficulty)


@app.route("/admin/quiz-history/view/<int:result_id>")
def admin_quiz_result_view(result_id):
    guard=admin_required()
    if guard:return guard
    r=_admin_fetchone("""SELECT qr.id,u.name,u.email,qr.subject,qr.difficulty,qr.score,qr.total_questions,qr.percentage,qr.completed_at,u.house FROM quiz_results qr JOIN users u ON u.id=qr.user_id WHERE qr.id=%s""",(result_id,))
    if not r:return redirect(url_for("admin_quiz_history"))
    result={"id":r[0],"name":r[1],"email":r[2],"subject":r[3],"difficulty":r[4],"score":r[5],"total":r[6],"percentage":float(r[7] or 0),"completed_at":r[8],"house":r[9]}
    return render_template("admin_quiz_result_view.html",admin_name=session.get("admin_name","Administrator"),result=result)


@app.route("/admin/quiz-history/delete/<int:result_id>", methods=["POST"])
def admin_delete_quiz_result(result_id):
    guard=admin_required()
    if guard:return guard
    connection=None; cursor=None
    try:
        connection=get_db_connection(); cursor=connection.cursor(); cursor.execute("DELETE FROM quiz_results WHERE id=%s",(result_id,)); connection.commit()
    except Exception as e:
        if connection: connection.rollback()
        print("Admin delete quiz result error:",e)
    finally:
        if cursor:cursor.close()
        if connection:connection.close()
    return redirect(url_for("admin_quiz_history"))


@app.route("/admin/houses")
def admin_houses():
    guard=admin_required()
    if guard:return guard
    current={x["house"]:x for x in get_current_house_totals()}; all_time={x["house"]:x for x in get_all_time_house_totals()}
    members={h:[] for h in HOUSE_NAMES}
    for r in _admin_fetchall("SELECT id,name,email,house FROM users WHERE house IS NOT NULL ORDER BY house,name"):
        members.setdefault(r[3],[]).append({"id":r[0],"name":r[1],"email":r[2]})
    history=[]
    for r in _admin_fetchall("""SELECT u.name,hpe.house_name,hpe.points,hpe.subject,hpe.difficulty,hpe.score,hpe.total_questions,hpe.created_at FROM house_point_events hpe JOIN users u ON u.id=hpe.user_id ORDER BY hpe.created_at DESC,hpe.id DESC LIMIT 200"""):
        history.append({"student":r[0],"house":r[1],"points":r[2],"subject":r[3],"difficulty":r[4],"score":r[5],"total":r[6],"created_at":r[7]})
    return render_template("admin_houses.html",admin_name=session.get("admin_name","Administrator"),houses=HOUSES,current=current,all_time=all_time,members=members,history=history)


@app.route("/admin/achievements")
def admin_achievements():
    guard=admin_required()
    if guard:return guard
    search=request.args.get("search","").strip(); params=[]; where=""
    if search:
        where="WHERE u.name ILIKE %s OR u.email ILIKE %s OR a.achievement_name ILIKE %s"; v=f"%{search}%"; params=[v,v,v]
    rows=_admin_fetchall(f"""SELECT a.id,u.name,u.email,a.achievement_name,a.description,a.earned_at FROM achievements a JOIN users u ON u.id=a.user_id {where} ORDER BY a.earned_at DESC,a.id DESC""",tuple(params))
    data=[{"id":r[0],"name":r[1],"email":r[2],"achievement":r[3],"description":r[4],"earned_at":r[5]} for r in rows]
    return render_template("admin_achievements.html",admin_name=session.get("admin_name","Administrator"),rows=data,search=search)


@app.route("/admin/achievements/delete/<int:achievement_id>", methods=["POST"])
def admin_delete_achievement(achievement_id):
    guard=admin_required()
    if guard:return guard
    connection=None;cursor=None
    try:
        connection=get_db_connection();cursor=connection.cursor();cursor.execute("DELETE FROM achievements WHERE id=%s",(achievement_id,));connection.commit()
    except Exception as e:
        if connection:connection.rollback()
        print("Admin delete achievement error:",e)
    finally:
        if cursor:cursor.close()
        if connection:connection.close()
    return redirect(url_for("admin_achievements"))


@app.route("/admin/certificates")
def admin_certificates():
    guard=admin_required()
    if guard:return guard
    search=request.args.get("search","").strip(); params=[]; where=""
    if search:
        where="WHERE c.certificate_id ILIKE %s OR c.title ILIKE %s OR u.name ILIKE %s OR u.email ILIKE %s";v=f"%{search}%";params=[v,v,v,v]
    rows=_admin_fetchall(f"""SELECT c.id,c.certificate_id,u.name,u.email,c.title,c.house_name,c.rank,c.points,c.issued_at,c.certificate_type FROM certificates c JOIN users u ON u.id=c.user_id {where} ORDER BY c.issued_at DESC,c.id DESC""",tuple(params))
    data=[{"id":r[0],"certificate_id":r[1],"name":r[2],"email":r[3],"title":r[4],"house":r[5],"rank":r[6],"points":r[7],"issued_at":r[8],"type":r[9]} for r in rows]
    return render_template("admin_certificates.html",admin_name=session.get("admin_name","Administrator"),rows=data,search=search)


@app.route("/admin/certificates/view/<int:certificate_id>")
def admin_certificate_view(certificate_id):
    guard=admin_required()
    if guard:return guard
    r=_admin_fetchone("""SELECT c.id,c.certificate_id,u.name,u.email,c.title,c.certificate_type,c.house_name,c.rank,c.points,c.issued_at FROM certificates c JOIN users u ON u.id=c.user_id WHERE c.id=%s""",(certificate_id,))
    if not r:return redirect(url_for("admin_certificates"))
    cert={"id":r[0],"certificate_id":r[1],"name":r[2],"email":r[3],"title":r[4],"type":r[5],"house":r[6],"rank":r[7],"points":r[8],"issued_at":r[9]}
    return render_template("admin_certificate_view.html",admin_name=session.get("admin_name","Administrator"),cert=cert)


@app.route("/admin/certificates/edit/<int:certificate_id>", methods=["GET", "POST"])
def admin_edit_certificate(certificate_id):
    """Edit a persisted certificate record from the Admin Arena."""
    guard = admin_required()
    if guard:
        return guard

    types = [
        ("house_excellence", "House Certificate of Excellence"),
        ("house_champion", "House Champion Certificate"),
        ("student_rank_1", "Student Rank #1"),
        ("student_rank_2", "Student Rank #2"),
        ("student_rank_3", "Student Rank #3"),
    ]
    connection = None
    cursor = None
    error = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        if request.method == "GET":
            cursor.execute("""
                SELECT c.id,c.certificate_id,c.title,c.certificate_type,
                       c.house_name,c.rank,c.points,c.issued_at,
                       u.name,u.email,u.id
                FROM certificates c
                JOIN users u ON u.id=c.user_id
                WHERE c.id=%s
            """, (certificate_id,))
            r = cursor.fetchone()
            if not r:
                return redirect(url_for("admin_certificates"))
            cert = {
                "id": r[0], "certificate_id": r[1], "title": r[2],
                "type": r[3], "house": r[4], "rank": r[5],
                "points": r[6], "issued_at": r[7],
                "name": r[8], "email": r[9], "user_id": r[10]
            }
            return render_template(
                "admin_certificate_form.html",
                admin_name=session.get("admin_name", "Administrator"),
                cert=cert, houses=HOUSE_NAMES, types=types, error=None
            )

        certificate_id_new = request.form.get("certificate_id", "").strip()
        title = request.form.get("title", "").strip()
        certificate_type = request.form.get("certificate_type", "").strip()
        house = request.form.get("house_name", "").strip() or None
        rank_raw = request.form.get("rank", "").strip()
        points_raw = request.form.get("points", "0").strip()

        if not certificate_id_new:
            error = "Certificate ID is required."
        elif len(certificate_id_new) > 100:
            error = "Certificate ID must be 100 characters or fewer."
        elif not title:
            error = "Certificate title is required."
        elif len(title) > 200:
            error = "Certificate title must be 200 characters or fewer."
        elif certificate_type not in {x[0] for x in types}:
            error = "Invalid certificate type."
        elif house and house not in HOUSE_NAMES:
            error = "Invalid House selected."

        rank = None
        points = 0
        if not error:
            try:
                rank = int(rank_raw) if rank_raw else None
                if rank is not None and rank not in (1, 2, 3):
                    error = "Rank must be 1, 2 or 3."
            except ValueError:
                error = "Rank must be a number."
        if not error:
            try:
                points = int(points_raw or 0)
                if points < 0:
                    error = "Points cannot be negative."
            except ValueError:
                error = "Points must be a number."

        cert = {
            "id": certificate_id, "certificate_id": certificate_id_new,
            "title": title, "type": certificate_type, "house": house,
            "rank": rank, "points": points,
            "issued_at": None,
            "name": "", "email": "", "user_id": None
        }

        cursor.execute("SELECT u.name,u.email,u.id,c.issued_at FROM certificates c JOIN users u ON u.id=c.user_id WHERE c.id=%s", (certificate_id,))
        owner = cursor.fetchone()
        if owner:
            cert["name"], cert["email"], cert["user_id"], cert["issued_at"] = owner

        if error:
            return render_template(
                "admin_certificate_form.html",
                admin_name=session.get("admin_name", "Administrator"),
                cert=cert, houses=HOUSE_NAMES, types=types, error=error
            )

        cursor.execute("SELECT id FROM certificates WHERE certificate_id=%s AND id<>%s", (certificate_id_new, certificate_id))
        if cursor.fetchone():
            error = "That Certificate ID is already in use."
            return render_template(
                "admin_certificate_form.html",
                admin_name=session.get("admin_name", "Administrator"),
                cert=cert, houses=HOUSE_NAMES, types=types, error=error
            )

        cursor.execute("""
            UPDATE certificates
            SET certificate_id=%s,title=%s,certificate_type=%s,
                house_name=%s,rank=%s,points=%s
            WHERE id=%s
        """, (certificate_id_new,title,certificate_type,house,rank,points,certificate_id))
        connection.commit()
        return redirect(url_for("admin_certificate_view", certificate_id=certificate_id))
    except Exception as e:
        if connection:
            connection.rollback()
        print("Admin edit certificate error:", e)
        return redirect(url_for("admin_certificates"))
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/admin/certificates/print/<int:certificate_id>")
def admin_certificate_print(certificate_id):
    guard = admin_required()
    if guard:
        return guard
    r = _admin_fetchone("""
        SELECT c.id,c.certificate_id,u.name,u.email,c.title,c.certificate_type,
               c.house_name,c.rank,c.points,c.issued_at
        FROM certificates c JOIN users u ON u.id=c.user_id
        WHERE c.id=%s
    """, (certificate_id,))
    if not r:
        return redirect(url_for("admin_certificates"))
    cert = {"id":r[0],"certificate_id":r[1],"name":r[2],"email":r[3],
            "title":r[4],"type":r[5],"house":r[6],"rank":r[7],
            "points":r[8],"issued_at":r[9]}
    house = cert.get("house") if cert.get("house") in HOUSE_NAMES else HOUSE_NAMES[0]
    return render_template(
        "certificate_record.html", certificate=cert,
        student_name=cert["name"], house=house, house_info=HOUSES[house],
        back_url=url_for("admin_certificate_view", certificate_id=certificate_id),
        admin_print=True
    )


@app.route("/admin/certificates/delete/<int:certificate_id>", methods=["POST"])
def admin_delete_certificate(certificate_id):
    guard=admin_required()
    if guard:return guard
    connection=None;cursor=None
    try:
        connection=get_db_connection();cursor=connection.cursor();cursor.execute("DELETE FROM certificates WHERE id=%s",(certificate_id,));connection.commit()
    except Exception as e:
        if connection:connection.rollback()
        print("Admin delete certificate error:",e)
    finally:
        if cursor:cursor.close()
        if connection:connection.close()
    return redirect(url_for("admin_certificates"))


@app.route("/admin/bookmarks")
def admin_bookmarks():
    guard=admin_required()
    if guard:return guard
    search=request.args.get("search","").strip();params=[];where=""
    if search:
        where="WHERE u.name ILIKE %s OR u.email ILIKE %s OR q.question_text ILIKE %s";v=f"%{search}%";params=[v,v,v]
    rows=_admin_fetchall(f"""SELECT b.id,b.question_id,u.name,u.email,q.question_text,q.subject,q.difficulty,b.created_at FROM bookmarks b JOIN users u ON u.id=b.user_id LEFT JOIN questions q ON q.id=b.question_id {where} ORDER BY b.created_at DESC,b.id DESC""",tuple(params))
    data=[{"id":r[0],"question_id":r[1],"name":r[2],"email":r[3],"question":r[4],"subject":r[5],"difficulty":r[6],"created_at":r[7]} for r in rows]
    return render_template("admin_bookmarks.html",admin_name=session.get("admin_name","Administrator"),rows=data,search=search)


@app.route("/admin/bookmarks/delete/<int:bookmark_id>", methods=["POST"])
def admin_delete_bookmark(bookmark_id):
    guard=admin_required()
    if guard:return guard
    connection=None;cursor=None
    try:
        connection=get_db_connection();cursor=connection.cursor();cursor.execute("DELETE FROM bookmarks WHERE id=%s",(bookmark_id,));connection.commit()
    except Exception as e:
        if connection:connection.rollback()
        print("Admin delete bookmark error:",e)
    finally:
        if cursor:cursor.close()
        if connection:connection.close()
    return redirect(url_for("admin_bookmarks"))


@app.route("/admin/analytics")
def admin_analytics():
    guard = admin_required()
    if guard:
        return guard

    data = {}

    def scalar(sql, params=()):
        row = _admin_fetchone(sql, params)
        return row[0] if row else 0

    data["students"] = int(scalar("SELECT COUNT(*) FROM users") or 0)
    data["active_students"] = int(scalar("SELECT COUNT(*) FROM users WHERE is_active=TRUE") or 0)
    data["questions"] = int(scalar("SELECT COUNT(*) FROM questions") or 0)
    data["attempts"] = int(scalar("SELECT COUNT(*) FROM quiz_results") or 0)
    data["avg_percentage"] = round(float(scalar("SELECT COALESCE(AVG(percentage),0) FROM quiz_results") or 0), 2)
    data["achievements"] = int(scalar("SELECT COUNT(*) FROM achievements") or 0)
    data["certificates"] = int(scalar("SELECT COUNT(*) FROM certificates") or 0)
    data["bookmarks"] = int(scalar("SELECT COUNT(*) FROM bookmarks") or 0)
    data["house_points"] = int(scalar("SELECT COALESCE(SUM(points),0) FROM house_point_events") or 0)

    # PostgreSQL does not allow a SELECT-list alias in GROUP BY.
    # Use a subquery so the performance level is grouped safely.
    performance_rows = _admin_fetchall("""
        SELECT performance_level, COUNT(*)
        FROM (
            SELECT CASE
                WHEN percentage >= 90 THEN 'Excellent'
                WHEN percentage >= 75 THEN 'Very Good'
                WHEN percentage >= 60 THEN 'Good'
                WHEN percentage >= 40 THEN 'Average'
                ELSE 'Needs Improvement'
            END AS performance_level
            FROM quiz_results
        ) AS performance_data
        GROUP BY performance_level
        ORDER BY CASE performance_level
            WHEN 'Excellent' THEN 1
            WHEN 'Very Good' THEN 2
            WHEN 'Good' THEN 3
            WHEN 'Average' THEN 4
            ELSE 5
        END
    """)
    data["performance_analytics"] = [
        {"name": r[0], "count": int(r[1] or 0)}
        for r in performance_rows
    ]

    subject_rows = _admin_fetchall("""
        SELECT subject, COUNT(*), COALESCE(AVG(percentage),0), COALESCE(MAX(percentage),0)
        FROM quiz_results GROUP BY subject ORDER BY COUNT(*) DESC, subject ASC
    """)
    data["subject_stats"] = [{"name": r[0], "attempts": int(r[1] or 0), "avg": round(float(r[2] or 0),2), "best": round(float(r[3] or 0),2)} for r in subject_rows]

    difficulty_rows = _admin_fetchall("""
        SELECT difficulty, COUNT(*), COALESCE(AVG(percentage),0), COALESCE(MAX(percentage),0)
        FROM quiz_results GROUP BY difficulty
        ORDER BY CASE difficulty WHEN 'Easy' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Hard' THEN 3 ELSE 4 END
    """)
    data["difficulty_stats"] = [{"name": r[0], "attempts": int(r[1] or 0), "avg": round(float(r[2] or 0),2), "best": round(float(r[3] or 0),2)} for r in difficulty_rows]

    data["house_stats"] = []
    for house_name in HOUSE_NAMES:
        info = HOUSES.get(house_name, {})
        members = int(scalar("SELECT COUNT(*) FROM users WHERE house=%s", (house_name,)) or 0)
        qs = _admin_fetchone("""
            SELECT COUNT(qr.id), COALESCE(AVG(qr.percentage),0), COALESCE(MAX(qr.percentage),0)
            FROM quiz_results qr JOIN users u ON u.id=qr.user_id WHERE u.house=%s
        """, (house_name,))
        current_points = int(scalar("""
            SELECT COALESCE(SUM(hpe.points),0) FROM house_point_events hpe
            JOIN users u ON u.id=hpe.user_id
            WHERE u.house=%s AND hpe.house_name=%s
        """, (house_name, house_name)) or 0)
        all_time_points = int(scalar("SELECT COALESCE(SUM(points),0) FROM house_point_events WHERE house_name=%s", (house_name,)) or 0)
        data["house_stats"].append({
            "name": house_name, "symbol": info.get("symbol",""), "title": info.get("title",""),
            "motto": info.get("motto",""), "members": members, "attempts": int(qs[0] or 0),
            "avg": round(float(qs[1] or 0),2), "best": round(float(qs[2] or 0),2),
            "points": current_points, "all_time_points": all_time_points
        })
    data["house_stats"].sort(key=lambda x: (-x["avg"], -x["points"], x["name"]))

    top_rows = _admin_fetchall("""
        SELECT u.id,u.name,u.house,COALESCE((SELECT SUM(points) FROM house_point_events hp WHERE hp.user_id=u.id),0),
               COUNT(qr.id),COALESCE(AVG(qr.percentage),0),COALESCE(MAX(qr.percentage),0)
        FROM users u LEFT JOIN quiz_results qr ON qr.user_id=u.id
        GROUP BY u.id,u.name,u.house ORDER BY 4 DESC,6 DESC,u.name ASC LIMIT 10
    """)
    data["top_students"] = [{"id":r[0],"name":r[1],"house":r[2] or "Unassigned","points":int(r[3] or 0),"attempts":int(r[4] or 0),"avg":round(float(r[5] or 0),2),"best":round(float(r[6] or 0),2)} for r in top_rows]

    if data["subject_stats"]:
        x=max(data["subject_stats"],key=lambda a:a["avg"]); data["best_subject"],data["best_subject_avg"]=x["name"],x["avg"]
        x=max(data["subject_stats"],key=lambda a:a["attempts"]); data["most_attempted_subject"],data["most_attempted_count"]=x["name"],x["attempts"]
    else:
        data["best_subject"],data["best_subject_avg"]="—",0; data["most_attempted_subject"],data["most_attempted_count"]="—",0

    if data["difficulty_stats"]:
        x=max(data["difficulty_stats"],key=lambda a:a["avg"]); data["best_difficulty"],data["best_difficulty_avg"]=x["name"],x["avg"]
        x=min(data["difficulty_stats"],key=lambda a:a["avg"]); data["most_challenging_difficulty"],data["most_challenging_avg"]=x["name"],x["avg"]
    else:
        data["best_difficulty"],data["best_difficulty_avg"]="—",0; data["most_challenging_difficulty"],data["most_challenging_avg"]="—",0

    if data["house_stats"]:
        x=max(data["house_stats"],key=lambda a:(a["avg"],a["points"])); data["best_house"],data["best_house_avg"],data["best_house_points"]=x["name"],x["avg"],x["points"]
    else:
        data["best_house"],data["best_house_avg"],data["best_house_points"]="—",0,0

    return render_template("admin_analytics.html", admin_name=session.get("admin_name","Administrator"), data=data)


@app.route("/admin/system", methods=["GET","POST"])
def admin_system():
    guard=admin_required()
    if guard:return guard
    message=request.args.get("message") or None
    error=request.args.get("error") or None
    if request.method=="POST":
        action=request.form.get("action","")
        try:
            if action=="sync_quizzes":
                if sync_quizzes_from_db(): message="Quiz engine synchronized from PostgreSQL."
                else: error="Question bank is empty or could not be synchronized."
            elif action=="ensure_tables":
                ensure_remember_tokens_table();ensure_bookmarks_table();ensure_admins_table();ensure_achievements_table();ensure_certificates_table();ensure_house_system();ensure_admin_question_fields();ensure_admin_system_fields();message="Database checks completed and required fields are ready."
            elif action=="cleanup_expired_tokens":
                connection=get_db_connection();cursor=connection.cursor();cursor.execute("DELETE FROM remember_tokens WHERE expires_at <= CURRENT_TIMESTAMP");removed=cursor.rowcount;connection.commit();cursor.close();connection.close();message=f"Removed {removed} expired Remember Me token(s)."
        except Exception as e:
            error="System operation failed.";print("Admin system error:",e)
    stats={
        "students":_admin_fetchone("SELECT COUNT(*) FROM users")[0],
        "questions":_admin_fetchone("SELECT COUNT(*) FROM questions")[0],
        "attempts":_admin_fetchone("SELECT COUNT(*) FROM quiz_results")[0],
        "achievements":_admin_fetchone("SELECT COUNT(*) FROM achievements")[0],
        "certificates":_admin_fetchone("SELECT COUNT(*) FROM certificates")[0],
        "bookmarks":_admin_fetchone("SELECT COUNT(*) FROM bookmarks")[0],
        "point_events":_admin_fetchone("SELECT COUNT(*) FROM house_point_events")[0],
        "postgresql_version":_admin_fetchone("SELECT version()")[0],
    }
    return render_template(
        "admin_system.html",
        admin_name=session.get("admin_name","Administrator"),
        stats=stats,
        # Flattened aliases keep the page compatible with both the
        # compact admin template and the richer system template.
        total_students=stats.get("students", 0),
        total_questions=stats.get("questions", 0),
        total_attempts=stats.get("attempts", 0),
        total_achievements=stats.get("achievements", 0),
        total_certificates=stats.get("certificates", 0),
        total_bookmarks=stats.get("bookmarks", 0),
        message=message,
        error=error
    )


# ---------------------------------------------------------
# ADMIN SYSTEM ACTION ALIASES
# ---------------------------------------------------------
# The current admin_system.html uses dedicated POST endpoints.
# Keep these aliases in addition to the main /admin/system action
# endpoint so the page works without requiring template rewrites.

@app.route("/admin/system/sync", methods=["GET", "POST"])
def admin_system_sync_alias():
    guard = admin_required()
    if guard:
        return guard
    if sync_quizzes_from_db():
        return redirect(url_for("admin_system", message="Quiz engine synchronized from PostgreSQL."))
    return redirect(url_for("admin_system", error="Question bank is empty or could not be synchronized."))


@app.route("/admin/system/verify", methods=["GET", "POST"])
def admin_system_verify_alias():
    guard = admin_required()
    if guard:
        return guard
    try:
        ensure_remember_tokens_table()
        ensure_bookmarks_table()
        ensure_admins_table()
        ensure_achievements_table()
        ensure_certificates_table()
        ensure_house_system()
        ensure_admin_question_fields()
        ensure_admin_system_fields()
        return redirect(url_for("admin_system", message="Database checks completed and required fields are ready."))
    except Exception as e:
        print("Admin database verification error:", e)
        return redirect(url_for("admin_system", error="Database verification failed."))


@app.route("/admin/system/clean-tokens", methods=["GET", "POST"])
def admin_system_clean_tokens_alias():
    guard = admin_required()
    if guard:
        return guard
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("DELETE FROM remember_tokens WHERE expires_at <= CURRENT_TIMESTAMP")
        removed = cursor.rowcount
        connection.commit()
        return redirect(url_for("admin_system", message=f"Removed {removed} expired Remember Me token(s)."))
    except Exception as e:
        if connection:
            connection.rollback()
        print("Admin token cleanup error:", e)
        return redirect(url_for("admin_system", error="Unable to clean expired tokens."))
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# STUDENT LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember_me = request.form.get("remember_me") == "on"

        if not email or not password:
            return render_template("login.html", error="Please enter your email and password.")

        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                "SELECT id, name, email, password, house, is_active FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
            if user is None:
                return render_template("login.html", error="Invalid email or password.")

            user_id, name, user_email, password_hash, house, is_active = user
            if not is_active:
                return render_template("login.html", error="This account is currently inactive. Please contact the administrator.")

            if not check_password_hash(password_hash, password):
                return render_template("login.html", error="Invalid email or password.")

            session["user_id"] = user_id
            session["user_name"] = name
            session["user_email"] = user_email
            session["user_house"] = house

            response = make_response(redirect(url_for("dashboard")))
            if remember_me:
                remember_token = create_remember_token(user_id)
                response.set_cookie(
                    REMEMBER_COOKIE_NAME,
                    remember_token,
                    max_age=REMEMBER_DAYS * 24 * 60 * 60,
                    httponly=True,
                    secure=False,
                    samesite="Lax"
                )
            return response
        except Exception as e:
            print("Login error:", e)
            return render_template("login.html", error="Login failed. Please try again.")
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    return render_template("login.html")

# =========================================================
# STUDENT LOGOUT
# =========================================================

@app.route("/logout")
def logout():
    remember_token = request.cookies.get(REMEMBER_COOKIE_NAME)
    clear_remember_token(remember_token)
    session.clear()
    response = make_response(redirect(url_for("home")))
    response.delete_cookie(REMEMBER_COOKIE_NAME)
    return response

# =========================================================
# STUDENT REGISTRATION
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        remember_me = request.form.get("remember_me") == "on"

        if not name or not email or not password or not confirm_password:
            return render_template("register.html", error="Please fill in all fields.")

        if len(name) > 100:
            return render_template("register.html", error="Name must be 100 characters or fewer.")

        if len(email) > 150:
            return render_template("register.html", error="Email must be 150 characters or fewer.")

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match.")

        if len(password) < 6:
            return render_template("register.html", error="Password must be at least 6 characters.")

        password_hash = generate_password_hash(password)
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return render_template("register.html", error="This email is already registered.")

            cursor.execute(
                """
                INSERT INTO users (name, email, password)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (name, email, password_hash)
            )

            user_id = cursor.fetchone()[0]
            connection.commit()

            session["user_id"] = user_id
            session["user_name"] = name
            session["user_email"] = email
            session["user_house"] = None

            response = make_response(redirect(url_for("select_house")))
            if remember_me:
                remember_token = create_remember_token(user_id)
                response.set_cookie(
                    REMEMBER_COOKIE_NAME,
                    remember_token,
                    max_age=REMEMBER_DAYS * 24 * 60 * 60,
                    httponly=True,
                    secure=False,
                    samesite="Lax"
                )
            return response

        except Exception as e:
            if connection:
                connection.rollback()
            print("Registration error:", e)
            return render_template("register.html", error="Registration failed. Please try again.")

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    return render_template("register.html")


# =========================================================
# STUDENT DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if not user_id:
        return redirect(url_for("login"))

    house = get_user_house(user_id)
    if not house:
        return redirect(url_for("select_house"))

    session["user_house"] = house

    # Automatically persist earned ranking certificates.
    award_champion_certificate_if_earned(user_id)
    award_student_ranking_certificate_if_earned(user_id)

    house_info = HOUSES[house]
    house_points = get_user_house_points(user_id)
    all_time_points = get_all_time_student_points(user_id)

    total_quizzes = 0
    best_score = 0
    achievements_count = 0

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM quiz_results WHERE user_id = %s",
            (user_id,)
        )
        total_quizzes = cursor.fetchone()[0] or 0

        cursor.execute(
            "SELECT COALESCE(MAX(percentage), 0) FROM quiz_results WHERE user_id = %s",
            (user_id,)
        )
        best_score = cursor.fetchone()[0] or 0

        cursor.execute(
            "SELECT COUNT(*) FROM achievements WHERE user_id = %s",
            (user_id,)
        )
        achievements_count = cursor.fetchone()[0] or 0

    except Exception as e:
        print("Dashboard database error:", e)

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template(
        "dashboard.html",
        total_quizzes=total_quizzes,
        best_score=best_score,
        achievements=achievements_count,
        house=house,
        house_info=house_info,
        house_points=house_points,
        all_time_points=all_time_points
    )


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    return render_template("home.html")


# =========================================================
# START QUIZ
# =========================================================

@app.route("/quiz", methods=["GET", "POST"])
def start_quiz():

    if request.method == "GET":
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if not get_user_house(session.get("user_id")):
            return redirect(url_for("select_house"))

        return render_template(
            "quiz.html",
            subjects=list(quizzes.keys()),
            difficulties=["Easy", "Medium", "Hard"]
        )

    if not session.get("user_id"):
        return redirect(url_for("login"))
    if not get_user_house(session.get("user_id")):
        return redirect(url_for("select_house"))

    subject = request.form.get("subject")
    difficulty = request.form.get("difficulty")

    if subject not in quizzes:
        return "Invalid subject", 400

    if difficulty not in quizzes[subject]:
        return "Invalid difficulty", 400

    questions = quizzes[subject][difficulty]

    return render_template(
        "quiz.html",
        questions=questions,
        subject=subject,
        difficulty=difficulty,
        subjects=list(quizzes.keys()),
        difficulties=["Easy", "Medium", "Hard"]
    )


# =========================================================
# SUBMIT QUIZ
# =========================================================

def build_explanation(question_text, correct_answer, subject):
    """Return a question-specific explanation for the Question Bank and Result review."""
    explanations = {
        "What is the chemical formula of water?": "Water is made of two hydrogen atoms and one oxygen atom, so its chemical formula is H2O.",
        "Which planet is called the Red Planet?": "Mars is called the Red Planet because iron minerals on its surface give it a reddish appearance.",
        "Which gas do humans need for breathing?": "Humans need oxygen for cellular respiration, the process cells use to release energy from food.",
        "Which organ pumps blood?": "The heart is a muscular organ that contracts to pump blood through the body's circulatory system.",
        "What force pulls objects toward Earth?": "Gravity attracts objects toward Earth and gives objects their weight near Earth's surface.",
        "Which star is closest to Earth?": "The Sun is the star closest to Earth and is the main source of light and heat for our planet.",
        "What is the boiling point of water?": "At normal atmospheric pressure, water boils at 100 C because it changes from liquid to gas at that temperature.",
        "Which part of a plant performs photosynthesis?": "Leaves contain chlorophyll and capture light energy, allowing the plant to make food through photosynthesis.",
        "Which organ is mainly used for breathing?": "The lungs exchange oxygen and carbon dioxide between the air and the blood, making them the main organs of breathing.",
        "Which vitamin is produced with sunlight exposure?": "Sunlight helps human skin produce vitamin D, which is important for calcium absorption and bone health.",
        "What is the center of an atom called?": "The nucleus is the dense center of an atom and contains protons and neutrons.",
        "Which particle has a negative charge?": "An electron carries a negative electric charge, while a proton is positive and a neutron is neutral.",
        "What is the basic unit of life?": "The cell is the basic structural and functional unit of living organisms.",
        "Which gas is most abundant in Earth's atmosphere?": "Nitrogen makes up about 78 percent of Earth's atmosphere, making it the most abundant atmospheric gas.",
        "What is the SI unit of force?": "The SI unit of force is the newton (N), defined through Newton's laws of motion.",
        "Which blood cells fight infections?": "White blood cells help the immune system identify and fight pathogens and other harmful substances.",
        "What process do plants use to make food?": "Photosynthesis uses light energy to convert carbon dioxide and water into glucose, releasing oxygen as a by-product.",
        "Which organ filters waste from blood?": "The kidneys filter the blood and remove wastes and excess water to form urine.",
        "What is the chemical symbol for sodium?": "Sodium's chemical symbol is Na, derived from its Latin name, natrium.",
        "Which planet has famous rings?": "Saturn is famous for its extensive system of bright rings made mainly of ice and rocky particles.",
        "Newton's second law is expressed as?": "Newton's second law states that force equals mass multiplied by acceleration, written as F = ma.",
        "What is known as the powerhouse of the cell?": "Mitochondria produce much of the cell's usable energy in the form of ATP, so they are called the powerhouse of the cell.",
        "Which particle determines atomic number?": "An element's atomic number equals its number of protons, so protons determine the atomic number.",
        "What is the pH of a neutral solution?": "A neutral aqueous solution has a pH of 7 at standard conditions, meaning hydrogen and hydroxide ion concentrations are balanced.",
        "Which law relates pressure and volume at constant temperature?": "Boyle's law states that pressure and volume are inversely related for a fixed amount of gas at constant temperature.",
        "Which type of bond involves sharing electrons?": "A covalent bond forms when atoms share pairs of electrons.",
        "What is the SI unit of electric current?": "The ampere (A) is the SI base unit used to measure electric current.",
        "Which organelle contains genetic material in most cells?": "In most eukaryotic cells, the nucleus contains the cell's main genetic material in the form of DNA.",
        "What is acceleration measured in?": "Acceleration is the rate of change of velocity, so its SI unit is metres per second squared (m/s2).",
        "Which phenomenon explains bending of light?": "Refraction is the bending of light when it passes between materials where its speed changes.",
        "What is 15 + 27?": "Adding 15 and 27 gives 42.",
        "What is 12 x 8?": "Multiplying 12 by 8 gives 96.",
        "What is the square of 9?": "The square of 9 is 9 × 9, which equals 81.",
        "What is 144 divided by 12?": "144 ÷ 12 equals 12 because 12 × 12 = 144.",
        "What is 2 to the power 3?": "2³ means multiplying 2 three times: 2 × 2 × 2 = 8.",
        "What is 50 percent of 100?": "50 percent means one-half, and one-half of 100 is 50.",
        "How many sides does a triangle have?": "A triangle is a polygon with exactly three sides and three angles.",
        "What is 7 x 7?": "7 × 7 equals 49.",
        "What is 100 - 37?": "Subtracting 37 from 100 gives 63.",
        "What comes next: 2, 4, 6, 8?": "The sequence increases by 2 each time, so the number after 8 is 10.",
        "If x + 7 = 15, what is x?": "Subtract 7 from both sides: x = 15 - 7 = 8.",
        "Area of a rectangle with length 10 and width 5?": "Rectangle area is length × width, so 10 × 5 = 50 square units.",
        "Average of 10, 20 and 30?": "The average is the sum divided by the number of values: (10 + 20 + 30) ÷ 3 = 20.",
        "What comes next: 2, 4, 8, 16?": "Each term is multiplied by 2, so 16 × 2 = 32.",
        "What is 25 percent of 200?": "25 percent is one-quarter, and one-quarter of 200 is 50.",
        "If 3x = 21, what is x?": "Divide both sides by 3: x = 21 ÷ 3 = 7.",
        "Perimeter of a square with side 6?": "A square has four equal sides, so its perimeter is 4 × 6 = 24 units.",
        "What is 15 squared?": "15² means 15 × 15, which equals 225.",
        "LCM of 4 and 6?": "The least common multiple is the smallest positive number divisible by both 4 and 6; that number is 12.",
        "HCF of 18 and 24?": "The highest common factor of 18 and 24 is 6, because 6 is the largest number that divides both exactly.",
        "Probability of getting heads on a fair coin?": "A fair coin has two equally likely outcomes, so the probability of heads is 1/2.",
        "If 2x + 5 = 17, what is x?": "Subtract 5 to get 2x = 12, then divide by 2 to get x = 6.",
        "Derivative of x squared?": "Using the power rule, the derivative of x² is 2x.",
        "What is the square root of 144?": "12 is the principal square root of 144 because 12 × 12 = 144.",
        "Sum of first 10 positive integers?": "Using n(n+1)/2, the sum is 10 × 11 ÷ 2 = 55.",
        "If a:b = 2:3 and b = 12, what is a?": "If 3 parts equal 12, one part is 4; therefore 2 parts equal 8.",
        "What is 5 factorial?": "5! means 5 × 4 × 3 × 2 × 1, which equals 120.",
        "Slope of y = 3x + 2?": "In y = mx + c, m is the slope. Here m = 3, so the slope is 3.",
        "Determinant of [[1,2],[3,4]]?": "For a 2×2 matrix [[a,b],[c,d]], the determinant is ad - bc = 1×4 - 2×3 = -2.",
        "What is log base 10 of 1000?": "10³ = 1000, so log base 10 of 1000 is 3.",
        "What does CPU stand for?": "CPU stands for Central Processing Unit, the main processor that executes instructions and performs calculations.",
        "What does RAM stand for?": "RAM stands for Random Access Memory, temporary working memory used by running programs and processes.",
        "Which language is used to structure web pages?": "HTML provides the structure and content of web pages using elements such as headings, paragraphs and links.",
        "Which symbol starts a comment in Python?": "In Python, a hash symbol (#) begins a single-line comment; the interpreter ignores the comment text.",
        "Which device is used to type text?": "A keyboard is an input device designed to enter letters, numbers and other commands into a computer.",
        "Which one is an operating system?": "Windows is an operating system that manages computer hardware, software resources and provides a user interface.",
        "What does URL stand for?": "URL stands for Uniform Resource Locator, the address used to locate a resource on the internet.",
        "Which device displays computer output?": "A monitor is an output device that displays visual information produced by the computer.",
        "Which language is commonly used for data analysis?": "Python is widely used for data analysis because of its libraries and tools for handling, processing and visualizing data.",
        "What is used to connect computers in a network?": "A network connects computers and other devices so they can communicate and share resources.",
        "Which data structure follows FIFO?": "A queue follows FIFO (First In, First Out), so the item inserted first is normally removed first.",
        "Which data structure follows LIFO?": "A stack follows LIFO (Last In, First Out), so the most recently added item is removed first.",
        "Which language is mainly used for database queries?": "SQL is designed for working with relational databases, including querying and modifying stored data.",
        "What does OOP stand for?": "OOP stands for Object-Oriented Programming, a programming approach organized around objects and classes.",
        "Which keyword creates a class in Python?": "The Python keyword class is used to define a class and its attributes and methods.",
        "Which algorithm is used for shortest path?": "Dijkstra's algorithm finds shortest paths from a source vertex in graphs with non-negative edge weights.",
        "What is the main purpose of an operating system?": "An operating system manages computer resources such as CPU, memory, storage and devices while providing services to applications.",
        "Which is a relational database?": "MySQL is a relational database management system that stores data in tables and supports SQL.",
        "What does API stand for?": "API stands for Application Programming Interface, a defined way for software components to communicate with each other.",
        "Which sorting algorithm repeatedly swaps adjacent elements?": "Bubble Sort repeatedly compares adjacent elements and swaps them when they are in the wrong order.",
        "Which data structure is commonly used in BFS?": "Breadth-First Search uses a queue so vertices are processed level by level in the order they are discovered.",
        "Which data structure is commonly used in DFS?": "Depth-First Search commonly uses a stack, either explicitly or through the program's recursion call stack.",
        "Average time complexity of binary search?": "Binary search halves the remaining sorted search space at each step, giving average time complexity O(log n).",
        "Which normal form removes partial dependency?": "Second Normal Form (2NF) removes partial dependency of a non-key attribute on part of a composite candidate key.",
        "Which algorithm finds a minimum spanning tree?": "Kruskal's algorithm builds a minimum spanning tree by selecting the lowest-weight edges while avoiding cycles.",
        "Which algorithm is commonly used for minimum spanning tree?": "Prim's algorithm grows a minimum spanning tree by repeatedly adding the lowest-weight edge connecting the tree to a new vertex.",
        "What is a primary key used for?": "A primary key uniquely identifies each record in a database table and prevents duplicate key values.",
        "Which protocol is commonly used for secure web browsing?": "HTTPS secures web communication by using HTTP over TLS, helping protect data exchanged between browser and server.",
        "What is recursion?": "Recursion is a technique in which a function calls itself, usually with a base case that stops further calls.",
        "Which memory is fastest among these?": "Cache memory is very fast memory located close to the CPU and stores frequently needed data and instructions.",
        "Which instrument has black and white keys?": "A piano has a keyboard made of black and white keys that control its notes.",
        "Which movie series features Hogwarts?": "Hogwarts is the fictional school of witchcraft and wizardry featured in the Harry Potter series.",
        "Which platform streams movies and shows?": "Netflix is a streaming platform that provides movies, television shows and other video content.",
        "Which sport is played at Wimbledon?": "Wimbledon is a major tennis tournament played on grass courts in London.",
        "Who is known as the Dark Knight?": "Batman is commonly known as the Dark Knight, a superhero associated with Gotham City.",
        "Which character lives in a pineapple under the sea?": "SpongeBob SquarePants is the fictional character who lives in a pineapple under the sea in Bikini Bottom.",
        "Which is mainly a music streaming service?": "Spotify is primarily a music and audio streaming service offering songs, albums, podcasts and more.",
        "Which award is associated with cinema?": "The Oscar, or Academy Award, is one of the best-known awards recognizing achievements in filmmaking.",
        "Which superhero uses Mjolnir?": "Thor is the Marvel superhero traditionally associated with Mjolnir, his enchanted hammer.",
        "Which game is played with a bat and ball?": "Cricket is a bat-and-ball sport in which players score runs while batting and defend wickets while fielding.",
        "What does CGI mean?": "CGI stands for Computer-Generated Imagery, which is used to create or enhance visual elements digitally.",
        "Which genre commonly features futuristic technology?": "Science fiction commonly explores futuristic technology, science and imagined worlds or societies.",
        "Which instrument commonly has six strings?": "A standard guitar commonly has six strings, which are tuned and played to produce different notes and chords.",
        "Which award is mainly associated with music?": "The Grammy Awards recognize achievements in recorded music and are among the major music awards.",
        "Which sport frequently uses the term hat-trick?": "The term hat-trick is commonly used in football when a player scores three goals in one match.",
        "What is a screenplay used for?": "A screenplay provides the written plan for a film, including scenes, dialogue, actions and other production details.",
        "Which device records professional audio?": "A microphone converts sound into an electrical or digital signal so it can be recorded or processed.",
        "What does a director primarily do?": "A film director guides the creative production, including performances, visual storytelling and decisions about how scenes are presented.",
        "Which genre is intended to make audiences laugh?": "Comedy is a genre designed primarily to entertain and make audiences laugh through humorous situations or dialogue.",
        "What is a sequel?": "A sequel continues the story or characters introduced in an earlier film, book, game or other work.",
        "What is diegetic sound?": "Diegetic sound originates within the story world and can be heard as part of the events or environment experienced by the characters.",
        "What does cinematography mainly concern?": "Cinematography concerns the visual creation of a film, including camera work, framing, lighting, lenses and movement.",
        "What is a montage?": "A montage is a sequence of edited shots placed together to compress time, show development or create an idea or mood.",
        "What is an ensemble cast?": "An ensemble cast is a group of several important performers who share major roles rather than having only one central performer.",
        "What is ADR in film production?": "ADR means Automated Dialogue Replacement, a process of recording replacement dialogue after filming to improve or change the original audio.",
        "What is a film score?": "A film score is original music composed or selected to support a film's emotions, atmosphere and storytelling.",
        "What does mise-en-scene refer to?": "Mise-en-scène refers to the elements arranged within a scene, such as setting, props, lighting, costume and actor placement.",
        "What is a plot twist?": "A plot twist is an unexpected development that changes the audience's understanding of the story or its events.",
        "What is an adaptation?": "An adaptation transforms a story or other source material into a different form, such as turning a novel into a film.",
        "What does a film editor primarily control?": "A film editor controls the arrangement and timing of shots, shaping pacing, continuity and the final flow of the story."
    }
    return explanations.get(question_text, f"{correct_answer} is the correct answer because it matches the concept asked in this question.")


def build_review_explanation(question_text, user_answer, correct_answer, subject, status):
    """Create personalized learner feedback using the question-specific explanation."""
    concept = build_explanation(question_text, correct_answer, subject)

    if status == "correct":
        return f"Correct! You selected {user_answer}, and it is the right answer. {concept}"

    if status == "wrong":
        return (
            f"Your answer was {user_answer}, but the correct answer is {correct_answer}. "
            f"Why your answer is wrong: {user_answer} does not satisfy what the question asks. "
            f"Why the correct answer is right: {concept}"
        )

    return f"You did not attempt this question. The correct answer is {correct_answer}. {concept}"



@app.route("/achievements")
def achievements_page():
    """Render the student's premium achievements and badge collection."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    achievements = get_user_achievements(user_id)
    earned_names = {item["name"] for item in achievements}

    total_attempts = 0
    perfect_count = 0
    subjects_played = 0
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM quiz_results WHERE user_id = %s",
            (user_id,)
        )
        total_attempts = cursor.fetchone()[0] or 0

        cursor.execute(
            "SELECT COUNT(*) FROM quiz_results WHERE user_id = %s AND percentage = 100",
            (user_id,)
        )
        perfect_count = cursor.fetchone()[0] or 0

        cursor.execute(
            "SELECT COUNT(DISTINCT subject) FROM quiz_results WHERE user_id = %s",
            (user_id,)
        )
        subjects_played = cursor.fetchone()[0] or 0

    except Exception as e:
        print("Achievements page database error:", e)
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    badge_catalog = [
        {
            "name": "Initiate",
            "icon": "✦",
            "class": "initiate",
            "tier": "Level I",
            "requirement": "Complete 1 quiz",
            "description": "Your first step into the quiz journey.",
            "progress": min(total_attempts, 1),
            "target": 1,
            "unit": "quiz"
        },
        {
            "name": "Knight",
            "icon": "♞",
            "class": "knight",
            "tier": "Level II",
            "requirement": "Complete 3 quizzes",
            "description": "Consistency begins to shape your skill.",
            "progress": min(total_attempts, 3),
            "target": 3,
            "unit": "quizzes"
        },
        {
            "name": "Elite",
            "icon": "◆",
            "class": "elite",
            "tier": "Level III",
            "requirement": "Complete 5 quizzes",
            "description": "You have entered the Elite tier.",
            "progress": min(total_attempts, 5),
            "target": 5,
            "unit": "quizzes"
        },
        {
            "name": "Champion",
            "icon": "♛",
            "class": "champion",
            "tier": "Level IV",
            "requirement": "Complete 10 quizzes",
            "description": "Champion-level commitment and momentum.",
            "progress": min(total_attempts, 10),
            "target": 10,
            "unit": "quizzes"
        },
        {
            "name": "Grandmaster",
            "icon": "♜",
            "class": "grandmaster",
            "tier": "Level V",
            "requirement": "Complete 20 quizzes",
            "description": "The highest core mastery milestone.",
            "progress": min(total_attempts, 20),
            "target": 20,
            "unit": "quizzes"
        },
        {
            "name": "Perfect Score",
            "icon": "100",
            "class": "perfect",
            "tier": "Special",
            "requirement": "Score 100% in a quiz",
            "description": "Accuracy at its absolute peak.",
            "progress": 1 if perfect_count > 0 else 0,
            "target": 1,
            "unit": "perfect score"
        },
        {
            "name": "Subject Expert",
            "icon": "◎",
            "class": "expert",
            "tier": "Special",
            "requirement": "Complete 3 quizzes in one subject",
            "description": "Deepen your knowledge in a subject.",
            "progress": 1 if "Subject Expert" in earned_names else 0,
            "target": 1,
            "unit": "subject mastery"
        },
        {
            "name": "Quiz Explorer",
            "icon": "✧",
            "class": "explorer",
            "tier": "Special",
            "requirement": "Play all 4 subjects",
            "description": "Explore every subject in the application.",
            "progress": min(subjects_played, 4),
            "target": 4,
            "unit": "subjects"
        },
    ]

    unlocked_count = len(earned_names.intersection({b["name"] for b in badge_catalog}))
    core_levels = ["Initiate", "Knight", "Elite", "Champion", "Grandmaster"]
    next_level = next((b for b in badge_catalog if b["name"] in core_levels and b["name"] not in earned_names), None)

    return render_template(
        "achievements.html",
        achievements=achievements,
        earned_names=earned_names,
        badge_catalog=badge_catalog,
        unlocked_count=unlocked_count,
        total_badges=len(badge_catalog),
        total_attempts=total_attempts,
        perfect_count=perfect_count,
        subjects_played=subjects_played,
        next_level=next_level
    )

@app.route("/api/achievements")
def get_achievements():
    if not session.get("user_id"):
        return {
            "success": False,
            "message": "Please login first."
        }, 401

    try:
        achievements = get_user_achievements(session["user_id"])
        return {
            "success": True,
            "achievements": achievements,
            "count": len(achievements)
        }
    except Exception as e:
        print("Get achievements error:", e)
        return {
            "success": False,
            "message": "Unable to load achievements."
        }, 500


@app.route("/api/bookmarks")
def get_bookmarks():
    if not session.get("user_id"):
        return {
            "success": False,
            "message": "Please login first."
        }, 401

    try:
        bookmarked_ids = get_bookmarked_question_ids(
            session["user_id"]
        )

        return {
            "success": True,
            "bookmarks": sorted(bookmarked_ids),
            "count": len(bookmarked_ids)
        }

    except Exception as e:
        print("Get bookmarks error:", e)
        return {
            "success": False,
            "message": "Unable to load saved questions."
        }, 500


@app.route("/bookmark/<int:question_id>", methods=["POST"])
def toggle_bookmark(question_id):
    if not session.get("user_id"):
        return {"success": False, "message": "Please login first."}, 401

    if question_id < 1:
        return {"success": False, "message": "Invalid question ID."}, 400

    try:
        action = toggle_bookmark_in_db(session["user_id"], question_id)
        bookmarked_ids = get_bookmarked_question_ids(session["user_id"])
        return {
            "success": True,
            "action": action,
            "question_id": question_id,
            "count": len(bookmarked_ids)
        }
    except Exception as e:
        print("Bookmark error:", e)
        return {"success": False, "message": "Bookmark operation failed."}, 500


@app.route("/saved-questions")
def saved_questions():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    bookmarked_ids=get_bookmarked_question_ids(session["user_id"])
    if not bookmarked_ids:
        return render_template("question_bank.html",questions=[],subjects=["Science","Mathematics","Computer Science","Entertainment"],difficulties=["Easy","Medium","Hard"],selected_subject="All",selected_difficulty="All",search_query="",saved_only=True)
    placeholders=",".join(["%s"]*len(bookmarked_ids))
    rows=_admin_fetchall(f"SELECT id,subject,difficulty,question_text,option_a,option_b,option_c,option_d,correct_answer,COALESCE(explanation,'') FROM questions WHERE id IN ({placeholders}) ORDER BY id",tuple(sorted(bookmarked_ids)))
    saved=[]
    for r in rows:
        saved.append({"number":len(saved)+1,"question_id":r[0],"subject":r[1],"difficulty":r[2],"question":r[3],"options":[r[4],r[5],r[6],r[7]],"correct_answer":r[8],"bookmarked":True,"explanation":r[9] or build_explanation(r[3],r[8],r[1])})
    return render_template("question_bank.html",questions=saved,subjects=["Science","Mathematics","Computer Science","Entertainment"],difficulties=["Easy","Medium","Hard"],selected_subject="All",selected_difficulty="All",search_query="",saved_only=True)


@app.route("/question-bank")
def question_bank():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    selected_subject=request.args.get("subject","All")
    selected_difficulty=request.args.get("difficulty","All")
    search_query=request.args.get("search","").strip()
    subjects=["Science","Mathematics","Computer Science","Entertainment"]
    difficulties=["Easy","Medium","Hard"]
    if selected_subject not in subjects and selected_subject!="All": selected_subject="All"
    if selected_difficulty not in difficulties and selected_difficulty!="All": selected_difficulty="All"
    conditions=[];params=[]
    if selected_subject!="All": conditions.append("subject=%s");params.append(selected_subject)
    if selected_difficulty!="All": conditions.append("difficulty=%s");params.append(selected_difficulty)
    if search_query:
        conditions.append("(question_text ILIKE %s OR option_a ILIKE %s OR option_b ILIKE %s OR option_c ILIKE %s OR option_d ILIKE %s OR correct_answer ILIKE %s)")
        v=f"%{search_query}%";params += [v]*6
    where="WHERE "+" AND ".join(conditions) if conditions else ""
    rows=_admin_fetchall(f"SELECT id,subject,difficulty,question_text,option_a,option_b,option_c,option_d,correct_answer,COALESCE(explanation,'') FROM questions {where} ORDER BY id ASC",tuple(params))
    bookmarked_ids=get_bookmarked_question_ids(session["user_id"])
    all_questions=[]
    for r in rows:
        all_questions.append({"number":len(all_questions)+1,"question_id":r[0],"subject":r[1],"difficulty":r[2],"question":r[3],"options":[r[4],r[5],r[6],r[7]],"correct_answer":r[8],"bookmarked":r[0] in bookmarked_ids,"explanation":r[9] or build_explanation(r[3],r[8],r[1])})
    return render_template("question_bank.html",questions=all_questions,subjects=subjects,difficulties=difficulties,selected_subject=selected_subject,selected_difficulty=selected_difficulty,search_query=search_query)


# =========================================================
# SUBMIT QUIZ + ANSWER REVIEW
# =========================================================

@app.route("/submit", methods=["POST"])
def submit():

    if not session.get("user_id"):
        return redirect(url_for("login"))

    current_house = get_user_house(session.get("user_id"))
    if not current_house:
        return redirect(url_for("select_house"))

    subject = request.form.get("subject")
    difficulty = request.form.get("difficulty")

    if subject not in quizzes:
        return "Invalid subject", 400

    if difficulty not in quizzes[subject]:
        return "Invalid difficulty", 400

    questions = quizzes[subject][difficulty]

    score = 0
    review = []

    for index, question_data in enumerate(questions):
        question_text = question_data[0]
        options = question_data[1]
        correct_answer = question_data[2]
        user_answer = request.form.get("q" + str(index))

        if user_answer == correct_answer:
            status = "correct"
            score += 1
        elif user_answer:
            status = "wrong"
        else:
            status = "unanswered"

        review.append({
            "number": index + 1,
            "question": question_text,
            "options": options,
            "user_answer": user_answer,
            "correct_answer": correct_answer,
            "status": status,
            "explanation": build_review_explanation(
                question_text,
                user_answer,
                correct_answer,
                subject,
                status
            )
        })

    total = len(questions)
    wrong = sum(item["status"] == "wrong" for item in review)
    unanswered = sum(item["status"] == "unanswered" for item in review)

    if total > 0:
        percentage = round((score / total) * 100)
    else:
        percentage = 0

    # Save this quiz attempt in PostgreSQL.
    newly_unlocked = []
    try:
        save_quiz_result(subject, difficulty, score, total, percentage)
        house_points_earned = award_house_points(
            session.get("user_id"),
            current_house,
            subject,
            difficulty,
            score,
            total
        )
        newly_unlocked = evaluate_achievements(
            session.get("user_id"),
            subject,
            score,
            total,
            percentage
        )
        # Automatically persist a Student Ranking certificate if the
        # completed quiz leaves this student in the All-Time Top 3.
        award_student_ranking_certificate_if_earned(
            session.get("user_id")
        )
    except Exception as e:
        # Keep the quiz result page working even if the database
        # temporarily has a connection problem.
        house_points_earned = 0
        print("Database save / achievement error:", e)

    return render_template(
        "result.html",
        score=score,
        total=total,
        wrong=wrong,
        unanswered=unanswered,
        percentage=percentage,
        subject=subject,
        difficulty=difficulty,
        review=review,
        newly_unlocked=newly_unlocked,
        house=current_house,
        house_info=HOUSES.get(current_house),
        house_points_earned=house_points_earned
    )


# =========================================================
# FOUR HOUSES — ROUTES
# =========================================================

@app.route("/select-house", methods=["GET", "POST"])
def select_house():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        house_name = request.form.get("house", "").strip()
        if house_name not in HOUSE_NAMES:
            return render_template("houses.html", houses=HOUSES, error="Please choose a valid House.")

        if set_user_house(user_id, house_name):
            session["user_house"] = house_name
            return redirect(url_for("dashboard"))

        return render_template("houses.html", houses=HOUSES, error="Unable to save your House. Please try again.")

    current_house = get_user_house(user_id)
    return render_template(
        "houses.html",
        houses=HOUSES,
        current_house=current_house
    )


@app.route("/change-house", methods=["POST"])
def change_house():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    house_name = request.form.get("house", "").strip()
    if house_name not in HOUSE_NAMES:
        return redirect(url_for("select_house"))

    if set_user_house(user_id, house_name):
        session["user_house"] = house_name
    return redirect(url_for("dashboard"))


@app.route("/leaderboards")
def leaderboards():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    house = get_user_house(user_id)
    if not house:
        return redirect(url_for("select_house"))

    current_house_totals = get_current_house_totals()
    all_time_house_totals = get_all_time_house_totals()
    current_students = get_current_house_leaderboard()
    all_time_students = get_all_time_student_leaderboard()
    house_students = get_current_house_leaderboard_by_house(house)

    return render_template(
        "leaderboards.html",
        houses=HOUSES,
        house=house,
        house_info=HOUSES[house],
        current_house_totals=current_house_totals,
        all_time_house_totals=all_time_house_totals,
        current_students=current_students,
        all_time_students=all_time_students,
        house_students=house_students
    )



@app.route("/my-certificates")
def my_certificates():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    # Sync certificates earned by the logged-in student.
    award_champion_certificate_if_earned(user_id)
    award_student_ranking_certificate_if_earned(user_id)

    connection = None
    cursor = None
    certificates = []

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT id, certificate_type, certificate_id, title,
                   house_name, rank, points, issued_at
            FROM certificates
            WHERE user_id = %s
            ORDER BY issued_at DESC, id DESC
        """, (user_id,))
        rows = cursor.fetchall()
        certificates = [
            {
                "id": row[0], "certificate_type": row[1],
                "certificate_id": row[2], "title": row[3],
                "house_name": row[4], "rank": row[5],
                "points": row[6], "issued_at": row[7]
            }
            for row in rows
        ]
    except Exception as e:
        print("My certificates database error:", e)
        certificates = []
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template("my_certificates.html", certificates=certificates)

@app.route("/certificate")
def certificate():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    house = get_user_house(user_id)
    if not house:
        return redirect(url_for("select_house"))

    current_students = get_current_house_leaderboard_by_house(house)
    all_time_students = get_all_time_student_leaderboard()

    current_rank = next(
        (item["rank"] for item in current_students
         if item.get("user_id") == user_id),
        None
    )
    all_time_rank = next(
        (item["rank"] for item in all_time_students
         if item.get("user_id") == user_id),
        None
    )

    rank_title = HOUSE_RANK_TITLES.get(current_rank, "House Contender")
    # Certificate points are the student's own lifetime points, not the whole House total.
    points = get_all_time_student_points(user_id)
    all_time_points = points

    certificate_record = save_house_certificate(
        user_id=user_id,
        house_name=house,
        rank=current_rank,
        points=points
    )

    if certificate_record:
        certificate_id = certificate_record["certificate_id"]
        issued_at = certificate_record["issued_at"].strftime("%d %B %Y")
    else:
        certificate_id = f"{HOUSES[house]['short']}-EXCELLENCE-{int(user_id):06d}"
        issued_at = datetime.now().strftime("%d %B %Y")

    # Open the persisted certificate record so the same certificate can always be
    # viewed and printed from My Certificates.
    return redirect(url_for("certificate_record", certificate_id=certificate_id))



@app.route("/certificate-record/<certificate_id>")
def certificate_record(certificate_id):
    """Display any persisted certificate owned by the logged-in student."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    r = None
    try:
        r = _admin_fetchone("""
            SELECT c.id,c.certificate_id,u.name,u.email,c.title,c.certificate_type,
                   c.house_name,c.rank,c.points,c.issued_at
            FROM certificates c JOIN users u ON u.id=c.user_id
            WHERE c.certificate_id=%s AND c.user_id=%s
        """, (certificate_id, user_id))
    except Exception as e:
        print("Certificate record fetch error:", e)
    if not r:
        return redirect(url_for("my_certificates"))
    cert = {"id":r[0],"certificate_id":r[1],"name":r[2],"email":r[3],
            "title":r[4],"type":r[5],"house":r[6],"rank":r[7],
            "points":r[8],"issued_at":r[9]}
    house = cert.get("house") if cert.get("house") in HOUSE_NAMES else HOUSE_NAMES[0]
    try:
        return render_template(
            "certificate_record.html", certificate=cert,
            student_name=cert["name"], house=house, house_info=HOUSES[house],
            back_url=url_for("my_certificates"), admin_print=False
        )
    except Exception as e:
        # Keep the certificate route usable even when an older local template
        # set does not contain certificate_record.html.
        print("Certificate template fallback:", e)
        return render_template_string("""
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>{{ certificate.title }}</title>
          <style>
            body{font-family:Arial,sans-serif;background:#111;color:#fff;margin:0;padding:30px}
            .card{max-width:850px;margin:30px auto;padding:45px;border:1px solid #777;border-radius:18px;background:#1b1b1b;text-align:center}
            .symbol{font-size:64px}.muted{color:#bbb}.points{font-size:34px;font-weight:700;margin:18px 0}
            a{display:inline-block;margin-top:20px;padding:12px 20px;border-radius:10px;background:#fff;color:#111;text-decoration:none}
          </style>
        </head>
        <body><div class="card">
          <div class="symbol">{{ house_info.symbol }}</div>
          <h1>{{ certificate.title }}</h1>
          <h2>{{ student_name }}</h2>
          <p class="muted">{{ house_info.title }} · {{ house }}</p>
          <div class="points">{{ certificate.points }} Points</div>
          <p>Certificate ID: {{ certificate.certificate_id }}</p>
          <p>Issued: {{ certificate.issued_at.strftime("%d %B %Y") if certificate.issued_at else "" }}</p>
          <a href="{{ back_url }}">Back to My Certificates</a>
        </div></body>
        </html>
        """, certificate=cert, student_name=cert["name"], house=house,
        house_info=HOUSES[house], back_url=url_for("my_certificates"))


@app.route("/student-rank-certificate/<certificate_id>")
def student_rank_certificate(certificate_id):
    """Display a previously earned Student Ranking certificate from PostgreSQL."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                c.certificate_id,
                c.title,
                c.house_name,
                c.rank,
                c.points,
                c.issued_at,
                u.name
            FROM certificates c
            JOIN users u ON u.id = c.user_id
            WHERE c.certificate_id = %s
              AND c.user_id = %s
              AND c.certificate_type IN (
                  'student_rank_1',
                  'student_rank_2',
                  'student_rank_3'
              )
            LIMIT 1
        """, (certificate_id, user_id))

        row = cursor.fetchone()

        if not row:
            return redirect(url_for("my_certificates"))

        saved_certificate_id = row[0]
        title = row[1]
        house = row[2]
        rank = int(row[3] or 0)
        points = int(row[4] or 0)
        issued_at = row[5]
        student_name = row[6]

        if house not in HOUSE_NAMES or rank not in (1, 2, 3):
            return redirect(url_for("my_certificates"))

        rank_titles = {
            1: "House Sovereign",
            2: "High Vanguard",
            3: "Elite Vanguard"
        }

        certificate = {
            "certificate_id": saved_certificate_id,
            "title": title,
            "house_name": house,
            "house_symbol": HOUSES[house]["symbol"],
            "rank": rank,
            "rank_title": rank_titles[rank],
            "points": points,
            "issued_at": issued_at,
            "student_name": student_name
        }

        return render_template(
            "student_rank_certificate.html",
            certificate=certificate
        )

    except Exception as e:
        print("Student ranking certificate display error:", e)
        return redirect(url_for("my_certificates"))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/house-champion-certificate")
def house_champion_certificate():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    all_time_house_totals = get_all_time_house_totals()
    champion = all_time_house_totals[0] if all_time_house_totals else {"house": HOUSE_NAMES[0], "points": 0}
    champion_house = champion["house"]

    # A student earns this certificate when their currently assigned House
    # is the all-time House Champion. Persist it in the database.
    student_house = get_user_house(user_id)
    certificate_record = award_champion_certificate_if_earned(user_id)

    if certificate_record:
        certificate_id = certificate_record["certificate_id"]
        issued_at = certificate_record["issued_at"].strftime("%d %B %Y")
    else:
        certificate_id = f"{HOUSES[champion_house]['short']}-CHAMPION-{int(user_id):06d}"
        issued_at = datetime.now().strftime("%d %B %Y")

    return render_template(
        "house_champion_certificate.html",
        student_name=session.get("user_name"),
        champion_house=champion_house,
        house_info=HOUSES[champion_house],
        points=champion["points"],
        certificate_id=certificate_id,
        issued_at=issued_at,
        is_earned=(student_house == champion_house)
    )



# =========================================================
# QUIZ HISTORY
# =========================================================

@app.route("/quiz-history")
def quiz_history():
    user_id = session.get("user_id")

    if not user_id:
        return redirect(url_for("login"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                subject,
                difficulty,
                score,
                total_questions,
                percentage,
                completed_at
            FROM quiz_results
            WHERE user_id = %s
            ORDER BY completed_at DESC
        """, (user_id,))

        rows = cursor.fetchall()

        history = [
            {
                "subject": row[0],
                "difficulty": row[1],
                "score": row[2],
                "total_questions": row[3],
                "percentage": row[4],
                "completed_at": row[5]
            }
            for row in rows
        ]

    except Exception as e:
        print("Quiz history database error:", e)
        history = []

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template(
        "quiz_history.html",
        history=history
    )

# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    # PostgreSQL is the source of truth for questions.
    # If the table is empty, the original built-in bank remains as fallback.
    sync_quizzes_from_db()
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "1") == "1"
    )
FROM python:3.11-slim

# התקנת כלי מערכת בסיסיים: git לצורך ה-Clone, ו-curl לבדיקות
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install semgrep

# הגדרת תיקיית העבודה של הסוכן שלנו
WORKDIR /app

# העתקת קובץ הדרישות של הפייתון 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --upgrade litellm google-generativeai

# העתקת קוד המקור של הסוכן לתוך הקונטיינר
COPY src/ ./src/

# פקודת ברירת המחדל - מריצה את הסוכן הראשי
CMD ["python", "src/main.py"]
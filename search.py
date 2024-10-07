import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from functools import wraps
from openai import OpenAI
from woocommerce import API
from dotenv import load_dotenv
import requests

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "your_secret_key")

# OpenAI and WooCommerce setup (unchanged)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)

wcapi = API(
    url=os.getenv("WC_URL"),
    consumer_key=os.getenv("WC_CONSUMER_KEY"),
    consumer_secret=os.getenv("WC_CONSUMER_SECRET"),
    version="wc/v3",
    timeout=30
)

categories = ["Nature", "Abstract", "Portrait", "Landscape"]

# WordPress authentication URL
WP_AUTH_URL = os.getenv("WP_AUTH_URL")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or not session['user'].get('is_admin'):
            flash('You do not have permission to access this page.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        response = requests.post(WP_AUTH_URL, json={'username': username, 'password': password})
        
        if response.status_code == 200:
            user_data = response.json()
            session['user'] = user_data
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# Admin dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html')

# Route to manage user access
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        user = User(username=username, password=generate_password_hash(password), is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        flash('User added successfully')
    
    users = User.query.all()
    return render_template('manage_users.html', users=users)

# Existing routes (add @login_required decorator to restrict access)
@app.route('/')
@login_required
def index():
    return render_template('index.html', categories=categories)

@app.route('/generate', methods=['POST'])
@login_required
def generate_images():
    data = request.json
    prompt = data['prompt']
    num_images = int(data['num_images'])

    image_urls = []
    try:
        for _ in range(num_images):
            response = client.images.generate(
                model="dall-e-3",
                prompt=prompt,
                size="1024x1024",
                quality="standard",
                n=1,
            )
            image_urls.append(response.data[0].url)
        return jsonify({"images": image_urls})
    except Exception as e:
        app.logger.error(f"Error generating images: {str(e)}")
        return jsonify({"error": f"Failed to generate images: {str(e)}"}), 400

@app.route('/list_for_sale', methods=['POST'])
@login_required
def list_for_sale():
    data = request.json
    image_urls = data['image_urls']
    category = data['category']
    
    listed_products = []
    for url in image_urls:
        # Create a new product in WooCommerce
        product_data = {
            "name": f"AI Generated Image - {category}",
            "type": "simple",
            "regular_price": "19.99",  # Set your desired price
            "description": "AI-generated image using DALL-E 3",
            "categories": [{"name": category}],
            "images": [{"src": url}]
        }
        
        try:
            app.logger.info(f"Attempting to list product with URL: {wcapi.url}")
            app.logger.info(f"Product data: {product_data}")
            response = wcapi.post("products", product_data)
            app.logger.info(f"Response status code: {response.status_code}")
            app.logger.info(f"Response content: {response.text}")
            if response.status_code == 201:
                listed_products.append(response.json())
            else:
                error_message = f"Failed to list product. Status code: {response.status_code}, Response: {response.text}"
                app.logger.error(error_message)
                return jsonify({"error": error_message}), 400
        except requests.exceptions.RequestException as e:
            error_message = f"Error listing product: {str(e)}"
            app.logger.error(error_message)
            return jsonify({"error": error_message}), 500

    return jsonify({"message": f"Successfully listed {len(listed_products)} products", "products": listed_products})

@app.route('/add_category', methods=['POST'])
@admin_required
def add_category():
    data = request.json
    new_category = data['category']
    if new_category not in categories:
        categories.append(new_category)
        return jsonify({"message": f"Category '{new_category}' added successfully", "categories": categories})
    else:
        return jsonify({"error": "Category already exists"}), 400

@app.route('/test_wc_connection')
def test_wc_connection():
    try:
        app.logger.info(f"Attempting to connect to WooCommerce API at URL: {wcapi.url}")
        response = wcapi.get("products", params={"per_page": 1})
        app.logger.info(f"Response status code: {response.status_code}")
        app.logger.info(f"Response headers: {response.headers}")
        app.logger.info(f"Response content: {response.text[:500]}...")  # Log first 500 characters
        return jsonify({
            "status": "success",
            "message": f"Connected to WooCommerce API. Status code: {response.status_code}",
            "url": wcapi.url,
            "response": response.json()
        })
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Failed to connect to WooCommerce API: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to connect to WooCommerce API: {str(e)}",
            "url": wcapi.url
        })

@app.route('/check_env')
def check_env():
    return jsonify({
        "WC_URL": os.getenv("WC_URL"),
        "WC_CONSUMER_KEY": os.getenv("WC_CONSUMER_KEY")[:5] + "...",  # Show only first 5 characters
        "WC_CONSUMER_SECRET": os.getenv("WC_CONSUMER_SECRET")[:5] + "..."  # Show only first 5 characters
    })

@app.route('/test_dns')
def test_dns():
    domain = os.getenv("WC_URL").replace("https://", "").replace("http://", "").split('/')[0]
    try:
        ip = socket.gethostbyname(domain)
        return jsonify({"status": "success", "domain": domain, "ip": ip})
    except socket.gaierror as e:
        return jsonify({"status": "error", "domain": domain, "error": str(e)})

@app.route('/test_wc_products')
def test_wc_products():
    try:
        app.logger.info(f"Attempting to retrieve products from WooCommerce API at URL: {wcapi.url}")
        response = wcapi.get("products", params={"per_page": 1})
        app.logger.info(f"Response status code: {response.status_code}")
        app.logger.info(f"Response content: {response.text[:500]}...")  # Log first 500 characters
        return jsonify({
            "status": "success",
            "message": f"Retrieved products from WooCommerce API. Status code: {response.status_code}",
            "url": wcapi.url,
            "response": response.json()
        })
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Failed to retrieve products from WooCommerce API: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve products from WooCommerce API: {str(e)}",
            "url": wcapi.url
        })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

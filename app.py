import os
from flask import Flask, render_template, redirect, url_for, flash, request,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import stripe

from datetime import datetime




app = Flask(__name__)

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
STRIPE_PUBLIC_KEY = "rhgrtyyvhjfntyj"  # This overwrites the imported value
STRIPE_SECRET_KEY = "ugdhvuidhguidj"  # This overwrites the imported value
stripe.api_key = STRIPE_SECRET_KEY
app.secret_key = 'gnuuuguhui'



db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User Loader (used by Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(300), nullable=True)  # Store image URL

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    products = db.Column(db.Text, nullable=False)  # Store product IDs as text
    total_price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create the database with the new table
with app.app_context():
    db.create_all()



@app.route('/products')
def products():
    return "<h1>Products Page (Coming Soon)</h1>"

@app.route('/cart')
@login_required
def cart():
    cart_items = []
    cart_items = Product.query.filter(Product.id.in_(session.get('cart', []))).all()
    if 'cart' in session:
        cart_items = Product.query.filter(Product.id.in_(session['cart'])).all()
    return render_template('cart.html', cart_items=cart_items)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[
            {
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': 'E-Commerce Order'},
                    'unit_amount': int(request.form['total_price']) * 100,  # Convert to cents
                },
                'quantity': 1,
            }
        ],
        mode='payment',
        success_url=url_for('payment_success', _external=True),
        cancel_url=url_for('payment_cancel', _external=True),
    )
    return redirect(session.url, code=303)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access Denied! Admins only.", "danger")
        return redirect(url_for('home'))

    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('home'))

    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = request.form['price']
        product.image_url = request.form['image_url']

        db.session.commit()
        flash("Product updated successfully!", "success")
        return redirect(url_for('admin'))

    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('home'))

    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()

    flash("Product deleted successfully!", "success")
    return redirect(url_for('admin'))

@app.route('/checkout')
@login_required
def checkout():
    if 'cart' not in session or not session['cart']:
        flash("Your cart is empty!", "warning")
        return redirect(url_for('home'))

    cart_items = Product.query.filter(Product.id.in_(session['cart'])).all()
    total_price = sum(item.price for item in cart_items)

    new_order = Order(user_id=current_user.id, products=str(session['cart']), total_price=total_price)
    db.session.add(new_order)
    db.session.commit()

    session.pop('cart', None)  # Clear cart after purchase
    flash("Purchase successful!", "success")
    return redirect(url_for('home'))

@app.route('/')
def home():
    products = Product.query.all()  # Fetch all products
    return render_template('home.html', products=products)

@app.route('/orders')
@login_required
def orders():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('orders.html', orders=orders)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/search')
def search():
    query = request.args.get('query', '').strip()
    if not query:
        flash("Please enter a search term!", "warning")
        return redirect(url_for('home'))

    products = Product.query.filter(Product.name.ilike(f"%{query}%")).all()
    return render_template('home.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password", "danger")
    
    return render_template('login.html')

@app.route('/filter_products')
def filter_products():
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)

    products = Product.query.filter(Product.price.between(min_price, max_price)).all()
    return render_template('home.html', products=products)

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/add_product', methods=['GET', 'POST'])
@login_required  # Only logged-in users can add products
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        image_url = request.form['image_url']

        new_product = Product(name=name, description=description, price=price, image_url=image_url)

        db.session.add(new_product)
        db.session.commit()
        
        flash("Product added successfully!", "success")
        return redirect(url_for('home'))

    return render_template('add_product.html')

@app.route('/payment_success')
def payment_success():
    flash("Payment Successful! Your order has been placed.", "success")
    return redirect(url_for('home'))

@app.route('/payment_cancel')
def payment_cancel():
    flash("Payment Cancelled.", "warning")
    return redirect(url_for('cart'))



if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Get port from environment, default to 5000
    app.run(host='0.0.0.0', port=port, debug=True

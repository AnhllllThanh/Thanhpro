const express = require('express'); 
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const MongoStore = require('connect-mongo');
const app = express();

// Cấu hình cơ sở dữ liệu
const dbURI = 'mongodb://localhost:27017/your-database-name';
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Đã kết nối với MongoDB'))
  .catch(err => console.error('Lỗi kết nối MongoDB:', err));

// Cấu hình session với MongoDB store
app.use(session({
  secret: 'secret-key', 
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: dbURI })
}));

// Cấu hình template engine
app.set('view engine', 'ejs');

// Middleware để parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// Cấu hình session và bảo mật password
const secretKey = crypto.randomBytes(32).toString('hex');

// Định nghĩa mô hình người dùng
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpiry: Date
});

// Mã hóa mật khẩu trước khi lưu
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model('User', userSchema);

// Route đăng ký
app.get('/register', (req, res) => {
  res.render('register', { error: req.session.error });
  req.session.error = null;
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    req.session.error = 'Vui lòng điền đầy đủ thông tin.';
    return res.redirect('/register');
  }

  const MIN_PASSWORD_LENGTH = 8;
  if (password.length < MIN_PASSWORD_LENGTH) {
    req.session.error = 'Mật khẩu phải có ít nhất 8 ký tự.';
    return res.redirect('/register');
  }

  try {
    // Kiểm tra xem username đã tồn tại chưa
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      req.session.error = 'Tên đăng nhập đã tồn tại.';
      return res.redirect('/register');
    }

    // Tạo người dùng mới và lưu vào MongoDB
    const newUser = new User({ username, password });
    await newUser.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Lỗi đăng ký:', err);
    req.session.error = 'Lỗi trong quá trình đăng ký.';
    res.redirect('/register');
  }
});

// Route đăng nhập
app.get('/login', (req, res) => {
  res.render('login', { error: req.session.error });
  req.session.error = null;
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    req.session.error = 'Vui lòng điền đầy đủ thông tin.';
    return res.redirect('/login');
  }

  try {
    // Kiểm tra xem người dùng có tồn tại không
    const user = await User.findOne({ username });
    if (!user) {
      req.session.error = 'Tên đăng nhập không chính xác.';
      return res.redirect('/login');
    }

    // So sánh mật khẩu đã mã hóa
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      req.session.error = 'Mật khẩu không đúng.';
      return res.redirect('/login');
    }

    // Đăng nhập thành công, lưu thông tin người dùng vào session
    req.session.user = user;
    req.session.success = 'Đăng nhập thành công!';
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Lỗi đăng nhập:', err);
    req.session.error = 'Lỗi trong quá trình đăng nhập.';
    res.redirect('/login');
  }
});

// Route dashboard (cần phải đăng nhập để truy cập)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.render('dashboard', { user: req.session.user, success: req.session.success });
  req.session.success = null;  // Xóa thông báo sau khi đã hiển thị
});

// Route đăng xuất
app.get('/logout', (req, res) => {
  // Hủy bỏ session của người dùng
  req.session.destroy((err) => {
    if (err) {
      console.log("Lỗi khi đăng xuất:", err);
    }
    // Sau khi hủy session, chuyển hướng người dùng về trang đăng nhập
    res.redirect('/login');
  });
});

// Lắng nghe cổng
app.listen(8080, () => {
  console.log('Server chạy trên cổng 8080');
});

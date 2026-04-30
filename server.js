const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('/mnt/d/web'));
app.use('/uploads', express.static('uploads'));

const db = new Pool({
    user: 'phong_admin',
    host: 'localhost',
    database: 'phong_demo',
    password: '123456',
    port: 5432,
});

const SECRET_KEY = "PHONG_BAO_MAT";

const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, 'avatar-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    try {
        await db.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashed]);
        res.status(201).send("Đăng ký thành công!");
    } catch (err) {
        res.status(400).send("Username đã tồn tại!");
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);

    if (result.rows.length > 0 && await bcrypt.compare(password, result.rows[0].password)) {
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });

        res.cookie('token', token, { httpOnly: true });
        return res.send({ message: "Đăng nhập thành công", user: { username: user.username } });
    }
    res.status(401).send("Sai tài khoản hoặc mật khẩu");
});

app.post('/update-profile', upload.single('avatar'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send("Chưa đăng nhập");

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const { fullname, age, phone, email } = req.body;
        const avatarUrl = req.file ? req.file.filename : null;

        let query = 'UPDATE users SET fullname=$1, age=$2, phone=$3, email=$4';
        let params = [fullname, age, phone, email];

        if (avatarUrl) {
            query += ', avatar=$5 WHERE id=$6';
            params.push(avatarUrl, decoded.id);
        } else {
            query += ' WHERE id=$5';
            params.push(decoded.id);
        }

        await db.query(query, params);
        res.send("Cập nhật thành công!");
    } catch (err) {
        res.status(401).send("Token không hợp lệ");
    }
});

app.get('/profile', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send("Chưa đăng nhập");

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const result = await db.query('SELECT username, fullname, email, phone, avatar FROM users WHERE id = $1', [decoded.id]);

        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).send("Không tìm thấy user");
        }
    } catch (err) {
        res.status(401).send("Token không hợp lệ hoặc đã hết hạn");
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.send("Đã đăng xuất");
});

app.listen(3000, () => console.log("Backend đang chạy tại http://localhost:3000"));

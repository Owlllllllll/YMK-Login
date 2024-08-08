const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const db = new sqlite3.Database(':memory:');

// 데이터베이스 테이블 생성
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT UNIQUE, password TEXT)"); // 이메일을 UNIQUE로 설정
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    // 입력값 검증
    if (!username || !email || !password) {
        return res.status(400).send("모든 필드를 입력해야 합니다.");
    }

    try {
        // 이메일과 사용자 이름 중복 체크를 동시에 수행
        const [existingEmail, existingUsername] = await Promise.all([
            new Promise((resolve, reject) => {
                db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
                    if (err) return reject(err);
                    resolve(row);
                });
            }),
            new Promise((resolve, reject) => {
                db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
                    if (err) return reject(err);
                    resolve(row);
                });
            }),
        ]);

        if (existingEmail) {
            return res.status(400).send("이미 존재하는 이메일입니다.");
        }

        const hashedPassword = bcrypt.hashSync(password, 8);
        
        db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hashedPassword], function(err) {
            if (err) {
                return res.status(500).send("회원가입 중 오류가 발생했습니다.");
            }
            res.status(201).send({ id: this.lastID, username, email });
        });
    } catch (error) {
        return res.status(500).send("서버 오류가 발생했습니다.");
    }
});



// 로그인
app.post('/login', (req, res) => {
    const { usernameOrEmail, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ? OR email = ?", [usernameOrEmail, usernameOrEmail], (err, user) => {
        if (err || !user) {
            return res.status(404).send("User not found.");
        }

        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).send({ auth: false, token: null });
        }

        const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: 86400 }); // 24 hours
        res.status(200).send({ auth: true, token });
    });
});

// 서버 시작
app.listen(3001, () => {
    console.log("Server is running on port 3001");
});

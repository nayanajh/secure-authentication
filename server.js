const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = 3000;

// Connect to SQLite database
const db = new sqlite3.Database("./database.db");

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration
app.use(
    session({
        secret: "secure-authentication-internship-secret",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            maxAge: 1000 * 60 * 60
        }
    })
);

// Create users table
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`);

// --------------------------------------------------
// Authentication middleware
// --------------------------------------------------

function requireLogin(req, res, next) {

    if (!req.session.userId) {
        return res.redirect("/login.html");
    }

    next();
}

// --------------------------------------------------
// Serve public files
// --------------------------------------------------

app.use(express.static(path.join(__dirname, "public"), {
    index: "index.html"
}));

// --------------------------------------------------
// REGISTER
// --------------------------------------------------

app.post("/register", async (req, res) => {

    const { username, password } = req.body;

    // Check empty fields
    if (!username || !password) {
        return res.status(400).send(`
            <h2>Registration Failed</h2>
            <p>Username and password are required.</p>
            <a href="/register.html">Go Back</a>
        `);
    }

    // Password length validation
    if (password.length < 8) {
        return res.status(400).send(`
            <h2>Registration Failed</h2>
            <p>Password must contain at least 8 characters.</p>
            <a href="/register.html">Go Back</a>
        `);
    }

    try {

        // Check whether username already exists
        db.get(
            "SELECT id FROM users WHERE username = ?",
            [username],
            async (err, existingUser) => {

                if (err) {
                    console.error(err);
                    return res.status(500).send("Database error.");
                }

                if (existingUser) {
                    return res.status(400).send(`
                        <h2>Registration Failed</h2>
                        <p>Username already exists.</p>
                        <a href="/register.html">Try Again</a>
                    `);
                }

                // Hash password
                const hashedPassword = await bcrypt.hash(password, 10);

                // Save user
                db.run(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    [username, hashedPassword],
                    function (err) {

                        if (err) {
                            console.error(err);
                            return res.status(500).send("Could not create account.");
                        }

                        // Redirect to login page
                        res.redirect("/login.html");
                    }
                );
            }
        );

    } catch (error) {

        console.error(error);

        res.status(500).send("Server error.");
    }
});

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post("/login", (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send(`
            <h2>Login Failed</h2>
            <p>Please enter username and password.</p>
            <a href="/login.html">Go Back</a>
        `);
    }

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {

            if (err) {
                console.error(err);
                return res.status(500).send("Database error.");
            }

            // Don't reveal whether username exists
            if (!user) {
                return res.status(401).send(`
                    <h2>Login Failed</h2>
                    <p>Invalid username or password.</p>
                    <a href="/login.html">Try Again</a>
                `);
            }

            // Compare entered password with hashed password
            const passwordMatch = await bcrypt.compare(
                password,
                user.password
            );

            if (!passwordMatch) {
                return res.status(401).send(`
                    <h2>Login Failed</h2>
                    <p>Invalid username or password.</p>
                    <a href="/login.html">Try Again</a>
                `);
            }

            // Create session
            req.session.userId = user.id;
            req.session.username = user.username;

            // Go to dashboard
            res.redirect("/dashboard.html");
        }
    );
});

// --------------------------------------------------
// PROTECTED DASHBOARD
// --------------------------------------------------

app.get("/dashboard.html", requireLogin, (req, res) => {

    res.sendFile(
        path.join(__dirname, "public", "dashboard.html")
    );
});

// --------------------------------------------------
// GET CURRENT USER
// --------------------------------------------------

app.get("/api/user", requireLogin, (req, res) => {

    res.json({
        username: req.session.username
    });
});

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

app.get("/logout", (req, res) => {

    req.session.destroy((err) => {

        if (err) {
            console.error(err);
            return res.status(500).send("Logout failed.");
        }

        res.clearCookie("connect.sid");

        res.redirect("/login.html");
    });
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {

    console.log(
        `Server running at http://localhost:${PORT}`
    );

});
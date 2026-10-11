require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const argon2 = require("argon2");
const { z } = require("zod");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, minlength: 2, maxlength: 60 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    refreshTokenHash: { type: String, default: null }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    content: { type: String, required: true, trim: true, maxlength: 2000 }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

const signupSchema = z.object({
    name: z.string().trim().min(2).max(60),
    email: z.string().trim().email().transform(value => value.toLowerCase()),
    password: z.string().min(8).max(128)
});

const loginSchema = z.object({
    email: z.string().trim().email().transform(value => value.toLowerCase()),
    password: z.string().min(1)
});

const messageSchemaInput = z.object({
    content: z.string().trim().min(1).max(2000)
});

function validate(schema) {
    return (req, res, next) => {
        const result = schema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({
                message: "Validation failed",
                errors: result.error.issues.map(issue => ({
                    field: issue.path.join("."),
                    message: issue.message
                }))
            });
        }
        req.validatedBody = result.data;
        next();
    };
}

function createAccessToken(user) {
    return jwt.sign(
        { role: user.role },
        process.env.JWT_ACCESS_SECRET,
        { subject: user._id.toString(), expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m" }
    );
}

function createRefreshToken(user) {
    return jwt.sign(
        { type: "refresh" },
        process.env.JWT_REFRESH_SECRET,
        { subject: user._id.toString(), expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || "7d" }
    );
}

function hashToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

async function authMiddleware(req, res, next) {
    try {
        const header = req.headers.authorization;
        if (!header || !header.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Bearer token is required" });
        }

        const token = header.split(" ")[1];
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        req.user = { id: payload.sub, role: payload.role };
        next();
    } catch (error) {
        return res.status(401).json({ message: "Invalid or expired access token" });
    }
}

function allowRoles(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: "Forbidden" });
        }
        next();
    };
}

app.get("/", (req, res) => {
    res.json({ message: "Saraha API is running" });
});

app.post("/auth/signup", validate(signupSchema), async (req, res, next) => {
    try {
        const { name, email, password } = req.validatedBody;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: "Email already exists" });
        }

        const passwordHash = await argon2.hash(password);
        const user = await User.create({ name, email, passwordHash });

        res.status(201).json({
            message: "Signup successful",
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (error) {
        next(error);
    }
});

app.post("/auth/login", validate(loginSchema), async (req, res, next) => {
    try {
        const { email, password } = req.validatedBody;
        const user = await User.findOne({ email });

        if (!user || !(await argon2.verify(user.passwordHash, password))) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);
        user.refreshTokenHash = hashToken(refreshToken);
        await user.save();

        res.json({
            message: "Login successful",
            tokenType: "Bearer",
            accessToken,
            refreshToken
        });
    } catch (error) {
        next(error);
    }
});

app.post("/auth/refresh", async (req, res, next) => {
    try {
        const { refreshToken } = req.body || {};
        if (!refreshToken) {
            return res.status(400).json({ message: "refreshToken is required" });
        }

        const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        if (payload.type !== "refresh") {
            return res.status(401).json({ message: "Invalid refresh token" });
        }

        const user = await User.findById(payload.sub);
        if (!user || user.refreshTokenHash !== hashToken(refreshToken)) {
            return res.status(401).json({ message: "Refresh token is invalid or already rotated" });
        }

        const newAccessToken = createAccessToken(user);
        const newRefreshToken = createRefreshToken(user);
        user.refreshTokenHash = hashToken(newRefreshToken);
        await user.save();

        res.json({
            tokenType: "Bearer",
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        });
    } catch (error) {
        res.status(401).json({ message: "Invalid or expired refresh token" });
    }
});

app.post("/auth/logout", authMiddleware, async (req, res, next) => {
    try {
        await User.findByIdAndUpdate(req.user.id, { refreshTokenHash: null });
        res.json({ message: "Logged out successfully" });
    } catch (error) {
        next(error);
    }
});

app.get("/users/me", authMiddleware, async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id).select("name email role createdAt");
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json({ user });
    } catch (error) {
        next(error);
    }
});

// Example admin-only route to demonstrate role authorization.
app.get("/admin", authMiddleware, allowRoles("admin"), (req, res) => {
    res.json({ message: "Welcome, admin" });
});

app.post("/messages/:userId", validate(messageSchemaInput), async (req, res, next) => {
    try {
        if (!mongoose.isValidObjectId(req.params.userId)) {
            return res.status(400).json({ message: "Invalid userId" });
        }

        const receiver = await User.findById(req.params.userId);
        if (!receiver) return res.status(404).json({ message: "Receiver not found" });

        const message = await Message.create({
            receiver: receiver._id,
            content: req.validatedBody.content
        });

        res.status(201).json({
            message: "Message sent successfully",
            data: { id: message._id, receiver: message.receiver, content: message.content, createdAt: message.createdAt }
        });
    } catch (error) {
        next(error);
    }
});

app.get("/messages", authMiddleware, async (req, res, next) => {
    try {
        const messages = await Message.find({ receiver: req.user.id }).sort({ createdAt: -1 });
        res.json({ count: messages.length, messages });
    } catch (error) {
        next(error);
    }
});

app.delete("/messages/:messageId", authMiddleware, async (req, res, next) => {
    try {
        if (!mongoose.isValidObjectId(req.params.messageId)) {
            return res.status(400).json({ message: "Invalid messageId" });
        }

        const message = await Message.findOneAndDelete({
            _id: req.params.messageId,
            receiver: req.user.id
        });

        if (!message) {
            return res.status(404).json({ message: "Message not found" });
        }

        res.json({ message: "Message deleted successfully" });
    } catch (error) {
        next(error);
    }
});

app.use((err, req, res, next) => {
    if (err && err.code === 11000) {
        return res.status(409).json({ message: "A record with this value already exists" });
    }

    console.error(err);
    res.status(500).json({ message: "Internal server error" });
});

async function start() {
    if (!process.env.MONGO_URI ||
        !process.env.JWT_ACCESS_SECRET ||
        !process.env.JWT_REFRESH_SECRET) {
        throw new Error("Set MONGO_URI, JWT_ACCESS_SECRET, and JWT_REFRESH_SECRET in .env");
    }

    await mongoose.connect(process.env.MONGO_URI);
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`Saraha API running on http://localhost:${port}`));
}

start().catch(error => {
    console.error("Failed to start server:", error.message);
    process.exit(1);
});

// server.js

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(bodyParser.json());
app.use(cors());

// Generate a token
const token = jwt.sign({ userId: '123' }, 'secretkey', { expiresIn: '1h' });

// Verify a token
try {
    const decodedToken = jwt.verify(token, 'secretkey');
    console.log(decodedToken); // { userId: '123', iat: 1644396415, exp: 1644396815 }
} catch (error) {
    console.error('Invalid token');
}

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/social-media', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error(err));

// Define User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 50
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        match: /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/
    },
    password: String,
    
});

const User = mongoose.model('User', userSchema);

// User Registration
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) throw new Error('User not found');
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) throw new Error('Invalid password');
        const token = jwt.sign({ userId: user._id }, 'secretkey');
        res.status(200).json({ token });
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

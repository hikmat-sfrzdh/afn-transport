const jwt = require("jsonwebtoken");
const { config } = require("../config/config");

const verifyToken = (req, res, next) => {
    if (req.method === 'OPTIONS') return next();

    try {
        const token = req.cookies?.token;
        if (!token) return res.status(401).json({ message: "No token provided" });

        req.user = jwt.verify(token, config.jwt_secret);
        next();
    } catch {
        res.status(401).json({ message: "Invalid or expired token" });
    }
};

const checkRole = (...roles) => (req, res, next) => {
    if (req.method === 'OPTIONS') return next();

    roles.includes(req.user?.role) 
        ? next() 
        : res.status(403).json({ message: `Access denied. Required roles: ${roles.join(", ")}` });
};

module.exports = { verifyToken, checkRole };
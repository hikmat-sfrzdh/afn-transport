const jwt = require("jsonwebtoken");
const { config } = require("../config/config");

const verifyToken = (req, res, next) => {
    try {
        let token = req.cookies?.token;
        if (!token && req.headers.authorization?.startsWith("Bearer ")) {
            token = req.headers.authorization.split(" ")[1];
        }
        if (!token) {
            return res.status(401).json({ message: "No token provided" });
        }
        const decoded = jwt.verify(token, config.jwt_secret);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
};
const checkRole = (...roles) =>{
    return (req, res, next) => {
        if(!req.user || !roles.includes(req.user.role)){
            return res.status(403).json({
                message: `Access denied. Required roles: ${roles.join(", ")}`
            });
        }
        next();
    }
}
module.exports = { verifyToken, checkRole }
const jwt = require("jsonwebtoken");

// Middleware for JWT authentication
const auth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    // Check if the header exists and starts with "Bearer"
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    // Verify the token using your secret
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach decoded user info to request
    req.user = {
      id: decoded.id,
      username: decoded.username, // include other properties if needed
      email: decoded.email,
    };

    next(); // Proceed to the next middleware or route
  } catch (err) {
    console.error("Auth error:", err.message);
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

module.exports = auth;

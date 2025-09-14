import jwt from "jsonwebtoken";

export const checkAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(403).json({ success: false, message: "No access" });
    }

    const token = authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : authHeader;

    if (!token) {
      return res.status(403).json({ success: false, message: "No access" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret123");
    req.userId = decoded.id;
    next();
  } catch (err) {
    console.error("checkAuth error:", err);
    return res.status(403).json({ success: false, message: "Invalid token" });
  }
};

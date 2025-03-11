// function authMiddleware(req, res, next) {
const authMiddleware = (req, res, next) => {

    const cookie = req.cookies["express-app-user"];
    const email = cookie;
    
    if (email) {
        req.userEmail = email;
        res.locals.userEmail = email;
    } else {
        req.userEmail = null;
        res.locals.userEmail = null;
    }

    next();
};

module.exports = authMiddleware;
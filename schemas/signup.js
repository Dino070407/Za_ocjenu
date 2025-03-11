const Joi = require("joi");

const schema = Joi.object({
    name: Joi.string().min(3).max(100).required(),
    email: Joi.string().email().required(),
    password: Joi.string().alphanum().min(6).required(),
    passwordConfirmation: Joi.string().required().valid(Joi.ref("password"))
});

module.exports = schema;
const Joi = require("joi");

const schema = Joi.object({
    name: Joi.string().min(3).max(100).required()
});

module.exports = schema;
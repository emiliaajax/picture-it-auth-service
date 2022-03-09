/**
 * Mongoose model User.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import mongoose from 'mongoose'
import bcrypt from 'bcryptjs'
import validator from 'validator'

const schema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    validate: [/^[A-Za-z][A-Za-z0-9_-]{2,255}$/, 'Please provide a valid username.']
  },
  password: {
    type: String,
    required: true,
    minlength: [10, 'The password must be at least 8 characters.'],
    maxlength: [256, 'The password must be less than 256 characters.']
  },
  firstName: {
    type: String,
    required: true,
    minLength: 1,
    maxLength: 256
  },
  lastName: {
    type: String,
    required: true,
    minLength: 1,
    maxLength: 256
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    validate: [validator.isEmail, 'Please provide a valid email address.']
  }
}, {
  timestamps: true,
  toJSON: {
    /**
     * Removes sensitive information by transforming the resulting object.
     *
     * @param {object} doc The mongoose document to be converted.
     * @param {object} ret The plain object response which has been converted.
     */
    transform: function (doc, ret) {
      delete ret._id
      delete ret.__v
    }
  },
  virtuals: true
})

schema.virtual('id').get(function () {
  return this.__id.toHexString()
})

// Before saving the password is salted and hashed.
schema.pre('save', async function () {
  this.password = await bcrypt.hash(this.password, 10)
})

// Inspired from https://mongoosejs.com/docs/middleware.html#post (retrieved at 2022-02-20)
schema.post('save', function (error, doc, next) {
  if (error.name === 'MongoServerError' & error.code === 11000) {
    if (Object.keys(error.keyValue)[0] === 'username') {
      throw new Error('The username is already taken!')
    } else if (Object.keys(error.keyValue)[0] === 'email') {
      throw new Error('The email is already in use!')
    }
  } else {
    next()
  }
})

/**
 * Authenticates an account.
 *
 * @param {string} username The username.
 * @param {string} password The password.
 * @returns {Promise} Resolves to a user object.
 */
schema.statics.authenticate = async function (username, password) {
  const account = await this.findOne({ username })
  if (!account || !(await bcrypt.compare(password, account.password))) {
    throw new Error('Invalid username or password.')
  }
  return account
}

// Creates a model using the schema.
export const Account = mongoose.model('Account', schema)

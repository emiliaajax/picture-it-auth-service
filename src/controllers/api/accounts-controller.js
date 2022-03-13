/**
 * Module for the AccountController.
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import jwt from 'jsonwebtoken'
import { Account } from '../../models/account.js'
import createError from 'http-errors'

/**
 * Encapsulates a controller.
 */
export class AccountsController {
  /**
   * Authenticates a user.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async login (req, res, next) {
    try {
      const account = await Account.authenticate(req.body.username, req.body.password)

      const payload = {
        sub: account.id,
        username: account.username,
        given_name: account.firstName,
        family_name: account.lastName,
        email: account.email
      }

      const accessToken = jwt.sign(payload, Buffer.from(process.env.ACCESS_TOKEN_SECRET, 'base64').toString('ascii'), {
        algorithm: 'RS256',
        expiresIn: process.env.ACCESS_TOKEN_LIFE
      })

      res
        .status(201)
        .json({
          access_token: accessToken
        })
    } catch (error) {
      const err = createError(401)
      err.cause = error
      next(err)
    }
  }

  /**
   * Registers a user.
   *
   * @param {object} req Express request object.
   * @param {object} res Express response object.
   * @param {Function} next Express next middleware function.
   */
  async register (req, res, next) {
    try {
      const account = new Account({
        username: req.body.username,
        password: req.body.password,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email
      })

      await account.save()

      res
        .status(201)
        .json({ id: account.id })
    } catch (error) {
      let err = error
      if (error.code === 11000 || error.name === 'ValidationError') {
        err = createError(400)
        err.cause = error
        err.message = 'The request cannot or will not be processed due to something that is perceived to be a client error (for example validation error).'
      }

      next(err)
    }
  }
}

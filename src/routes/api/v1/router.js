/**
 * API version 1 routes
 *
 * @author Emilia Hansson <eh222yn@student.lnu.se>
 * @version 1.0.0
 */

import express from 'express'
import { router as accountRouter } from './accounts-router.js'

export const router = express.Router()

router.get('/', (req, res) => res.json({
  message: 'Welcome to version 1 of this API!',
  endpoints: [
    {
      endpoint: 'POST /register',
      description: 'Registers a user.'
    },
    {
      endpoint: 'POST /login',
      description: 'Login user.'
    }
  ]
}))
router.use('/', accountRouter)

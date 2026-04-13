const express = require('express')
const router = express.Router()

const {
  getAllTopics, createTopic, updateTopic, deleteTopic, voteTopic,
  createLink, updateLink, deleteLink, voteLink
} = require('../controllers/controller')
const { requireLogin, requireRole } = require('../middlewares/auth')
const { showAdmin } = require('../controllers/authController')

router.get('/', getAllTopics)
router.post('/topics', requireLogin, createTopic)
router.post('/topics/:id/update', requireLogin, updateTopic)
router.post('/topics/:id/delete', requireLogin, requireRole('admin'), deleteTopic)
router.post('/topics/:id/vote', requireLogin, voteTopic)

router.post('/topics/:id/links', requireLogin, createLink)
router.post('/topics/:id/links/:linkId/update', requireLogin, updateLink)
router.post('/topics/:id/links/:linkId/delete', requireLogin, requireRole('admin'), deleteLink)
router.post('/topics/:id/links/:linkId/vote', requireLogin, voteLink)

router.get('/admin', requireLogin, requireRole('admin'), showAdmin)

module.exports = router

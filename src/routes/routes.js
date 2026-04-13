const express = require('express')
const router = express.Router()

const {
  getAllTopics, createTopic, updateTopic, deleteTopic, voteTopic,
  createLink, updateLink, deleteLink, voteLink
} = require('../controllers/controller')

router.get('/', getAllTopics)
router.post('/topics', createTopic)
router.post('/topics/:id/update', updateTopic)
router.post('/topics/:id/delete', deleteTopic)
router.post('/topics/:id/vote', voteTopic)

router.post('/topics/:id/links', createLink)
router.post('/topics/:id/links/:linkId/update', updateLink)
router.post('/topics/:id/links/:linkId/delete', deleteLink)
router.post('/topics/:id/links/:linkId/vote', voteLink)

module.exports = router

const db = require('../models/db')

// ── TOPICS ──

const getAllTopics = (req, res) => {
  const topics = db.prepare('SELECT * FROM topics ORDER BY votes DESC').all()
  const getLinks = db.prepare('SELECT * FROM links WHERE topic_id = ? ORDER BY votes DESC')
  for (const topic of topics) {
    topic.links = getLinks.all(topic.id)
  }
  res.render('index', { topics })
}

const createTopic = (req, res) => {
  db.prepare('INSERT INTO topics (title, description) VALUES (?, ?)').run(req.body.title, req.body.description)
  res.redirect('/')
}

const updateTopic = (req, res) => {
  db.prepare('UPDATE topics SET title = ?, description = ? WHERE id = ?').run(req.body.title, req.body.description, req.params.id)
  res.redirect('/')
}

const deleteTopic = (req, res) => {
  db.prepare('DELETE FROM topics WHERE id = ?').run(req.params.id)
  res.redirect('/')
}

const voteTopic = (req, res) => {
  const info = db.prepare('UPDATE topics SET votes = votes + 1 WHERE id = ?').run(req.params.id)
  if (info.changes === 0) return res.status(404).json({ error: 'Topic no encontrado' })
  const { votes } = db.prepare('SELECT votes FROM topics WHERE id = ?').get(req.params.id)
  res.json({ success: true, votes })
}

// ── LINKS ──

const createLink = (req, res) => {
  db.prepare('INSERT INTO links (topic_id, title, url) VALUES (?, ?, ?)').run(req.params.id, req.body.title, req.body.url)
  res.redirect('/')
}

const updateLink = (req, res) => {
  db.prepare('UPDATE links SET title = ?, url = ? WHERE id = ? AND topic_id = ?').run(req.body.title, req.body.url, req.params.linkId, req.params.id)
  res.redirect('/')
}

const deleteLink = (req, res) => {
  db.prepare('DELETE FROM links WHERE id = ? AND topic_id = ?').run(req.params.linkId, req.params.id)
  res.redirect('/')
}

const voteLink = (req, res) => {
  const info = db.prepare('UPDATE links SET votes = votes + 1 WHERE id = ? AND topic_id = ?').run(req.params.linkId, req.params.id)
  if (info.changes === 0) return res.status(404).json({ error: 'Link no encontrado' })
  const { votes } = db.prepare('SELECT votes FROM links WHERE id = ?').get(req.params.linkId)
  res.json({ success: true, votes })
}

module.exports = {
  getAllTopics, createTopic, updateTopic, deleteTopic, voteTopic,
  createLink, updateLink, deleteLink, voteLink
}

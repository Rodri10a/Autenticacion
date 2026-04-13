function toggleForm(id) {
  document.getElementById(id).classList.toggle('hidden')
}

document.addEventListener('DOMContentLoaded', () => {

  document.querySelectorAll('.vote-topic-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id
      const res = await fetch(`/topics/${id}/vote`, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
      const data = await res.json()
      if (data.success) document.getElementById(`votes-${id}`).textContent = `${data.votes} votos`
    })
  })

  document.querySelectorAll('.vote-link-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const { topicId, linkId } = btn.dataset
      const res = await fetch(`/topics/${topicId}/links/${linkId}/vote`, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
      const data = await res.json()
      if (data.success) document.getElementById(`link-votes-${linkId}`).textContent = `${data.votes} votos`
    })
  })

})

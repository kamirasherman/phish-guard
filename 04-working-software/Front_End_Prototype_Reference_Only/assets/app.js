function showToast(message = 'Action completed') {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('visible');
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => toast.classList.remove('visible'), 1800);
}

document.addEventListener('DOMContentLoaded', () => {
  const navToggle = document.getElementById('navToggle');
  const navLinks = document.getElementById('navLinks');

  navToggle.addEventListener('click', () => {
    const open = navLinks.classList.toggle('open');
    navToggle.setAttribute('aria-expanded', String(open));
  });

  navLinks.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => navLinks.classList.remove('open'));
  });

  document.getElementById('campaignForm').addEventListener('submit', event => {
    event.preventDefault();
    showToast('Campaign draft saved for demo');
  });

  document.getElementById('continueTraining').addEventListener('click', () => {
    showToast('Training started event recorded');
    window.location.hash = 'training';
  });

  document.querySelectorAll('.quiz-options button').forEach(button => {
    button.addEventListener('click', () => {
      document.querySelectorAll('.quiz-options button').forEach(option => option.classList.remove('correct', 'incorrect'));
      const feedback = document.getElementById('quizFeedback');
      if (button.dataset.correct === 'true') {
        button.classList.add('correct');
        feedback.textContent = 'Correct. Unusual or unrelated link destinations are strong phishing indicators.';
        feedback.style.color = 'var(--accent)';
      } else {
        button.classList.add('incorrect');
        feedback.textContent = 'Not quite. The strongest warning sign is the unrelated link destination.';
        feedback.style.color = 'var(--danger)';
      }
    });
  });

  document.getElementById('exportBtn').addEventListener('click', () => showToast('Mock report export prepared'));
});

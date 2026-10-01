(() => {
  const revealVideo = document.getElementById('phishguard-rickroll');
  const revealFallback = document.getElementById('rickroll-play-fallback');
  const trainingVideo = document.getElementById('phishguard-training-video');
  const trainingOverlay = document.getElementById('training-start-overlay');
  const startTrainingButton = document.getElementById('start-training-button');
  const trainingBox = document.getElementById('training-box');
  const trainingCompleteCta = document.getElementById('training-complete-cta');

  let trainingStarted = false;

  const playRevealWithAudio = async () => {
    if (!revealVideo || trainingStarted) return;
    revealVideo.muted = false;
    revealVideo.volume = 1.0;
    try {
      await revealVideo.play();
      if (revealFallback) revealFallback.hidden = true;
    } catch (error) {
      if (revealFallback) revealFallback.hidden = false;
    }
  };

  const stopReveal = () => {
    if (!revealVideo) return;
    revealVideo.pause();
    revealVideo.loop = false;
    try {
      revealVideo.currentTime = 0;
    } catch (error) {
      // Some browsers may not permit seeking until metadata is available.
    }
    if (revealFallback) revealFallback.hidden = true;
  };

  const startTraining = async () => {
    if (!trainingVideo) return;
    trainingStarted = true;
    stopReveal();
    if (trainingOverlay) trainingOverlay.hidden = true;

    trainingVideo.muted = false;
    trainingVideo.volume = 1.0;
    try {
      await trainingVideo.play();
    } catch (error) {
      // The button click is a user gesture, but leave native controls available
      // if a browser still requires a second explicit play action.
    }

    if (trainingBox && typeof trainingBox.scrollIntoView === 'function') {
      trainingBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  if (revealVideo) {
    revealVideo.addEventListener('loadedmetadata', playRevealWithAudio, { once: true });
    window.addEventListener('load', playRevealWithAudio, { once: true });
  }

  if (revealFallback) {
    revealFallback.addEventListener('click', playRevealWithAudio);
  }

  if (startTrainingButton) {
    startTrainingButton.addEventListener('click', startTraining);
  }

  if (trainingVideo && trainingCompleteCta) {
    trainingVideo.addEventListener('ended', () => {
      trainingCompleteCta.hidden = false;
      if (typeof trainingCompleteCta.scrollIntoView === 'function') {
        trainingCompleteCta.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  }

  const retryRevealOnInteraction = () => {
    if (!trainingStarted) playRevealWithAudio();
  };
  document.addEventListener('pointerdown', retryRevealOnInteraction, { once: true });
  document.addEventListener('keydown', retryRevealOnInteraction, { once: true });
})();

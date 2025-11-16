document.getElementById('phishingForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const formData = new FormData(e.target);
  const resultDiv = document.getElementById('result');
  const urlInput = document.getElementById('name');
  const testedUrl = urlInput.value;

  resultDiv.style.display = 'block';
  resultDiv.innerHTML = '<p style="color: #fff; background: #333; padding: 10px; border-radius: 5px;">Analyzing URL...</p>';

  try {
    const response = await fetch('/predict', {
      method: 'POST',
      body: formData
    });

    const data = await response.json();

    if (data.error) {
      resultDiv.style.backgroundColor = '#dc3545';
      resultDiv.innerHTML = `
        <h3 style="color: #fff;">Error</h3>
        <p style="color: #fff;">${data.error}</p>
        <p style="color: #fff; word-break: break-all; margin-top: 10px;"><strong>URL:</strong> ${testedUrl}</p>
      `;
    } else {
      const riskFactorsList = data.risk_factors ? data.risk_factors.map(f => `<li style="text-align: left; margin: 5px 0;">${f}</li>`).join('') : '';
      
      if (data.prediction === 'phishing') {
        resultDiv.style.backgroundColor = '#dc3545';
        resultDiv.innerHTML = `
          <h3 style="color: #fff; margin-bottom: 15px;">⚠️ PHISHING DETECTED!</h3>
          <p style="color: #fff; word-break: break-all; background: rgba(0,0,0,0.2); padding: 10px; border-radius: 5px; margin-bottom: 15px;"><strong>Tested URL:</strong> ${testedUrl}</p>
          <p style="color: #fff; font-size: 18px; margin-bottom: 10px;">${data.message}</p>
          <p style="color: #fff; font-weight: bold; font-size: 20px;">Risk Score: ${data.risk_score}/${data.max_score}</p>
          <div style="margin-top: 15px;">
            <p style="color: #fff; font-weight: bold; margin-bottom: 10px;">Risk Factors Detected:</p>
            <ul style="color: #fff; text-align: left; display: inline-block; margin: 0;">${riskFactorsList}</ul>
          </div>
        `;
      } else if (data.prediction === 'suspicious') {
        resultDiv.style.backgroundColor = '#ffc107';
        resultDiv.innerHTML = `
          <h3 style="color: #000; margin-bottom: 15px;">⚠️ SUSPICIOUS URL</h3>
          <p style="color: #000; word-break: break-all; background: rgba(0,0,0,0.1); padding: 10px; border-radius: 5px; margin-bottom: 15px;"><strong>Tested URL:</strong> ${testedUrl}</p>
          <p style="color: #000; font-size: 18px; margin-bottom: 10px;">${data.message}</p>
          <p style="color: #000; font-weight: bold; font-size: 20px;">Risk Score: ${data.risk_score}/${data.max_score}</p>
          <div style="margin-top: 15px;">
            <p style="color: #000; font-weight: bold; margin-bottom: 10px;">Risk Factors Detected:</p>
            <ul style="color: #000; text-align: left; display: inline-block; margin: 0;">${riskFactorsList}</ul>
          </div>
        `;
      } else {
        resultDiv.style.backgroundColor = '#28a745';
        resultDiv.innerHTML = `
          <h3 style="color: #fff; margin-bottom: 15px;">✓ RELATIVELY SAFE</h3>
          <p style="color: #fff; word-break: break-all; background: rgba(0,0,0,0.2); padding: 10px; border-radius: 5px; margin-bottom: 15px;"><strong>Tested URL:</strong> ${testedUrl}</p>
          <p style="color: #fff; font-size: 18px; margin-bottom: 10px;">${data.message}</p>
          <p style="color: #fff; font-weight: bold; font-size: 20px;">Risk Score: ${data.risk_score}/${data.max_score}</p>
          ${riskFactorsList ? `<div style="margin-top: 15px;">
            <p style="color: #fff; font-weight: bold; margin-bottom: 10px;">Notes:</p>
            <ul style="color: #fff; text-align: left; display: inline-block; margin: 0;">${riskFactorsList}</ul>
          </div>` : ''}
        `;
      }
    }
    
    // Scroll to result smoothly
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    
  } catch (error) {
    resultDiv.style.backgroundColor = '#dc3545';
    resultDiv.innerHTML = `
      <h3 style="color: #fff;">Error</h3>
      <p style="color: #fff;">Failed to analyze URL. Please try again.</p>
      <p style="color: #fff; word-break: break-all; margin-top: 10px;"><strong>URL:</strong> ${testedUrl}</p>
    `;
  }
});

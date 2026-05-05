/**
 * CardService rendering for the MailWatch Tower Gmail Add-on.
 */

var LRM = '\u200E';
var LARGE_DOT = '\u2B24';

function buildAnalysisResultCard(response) {
  response = response || {};
  var verdict = response && response.verdict ? String(response.verdict) : 'Unknown';
  var verdictColor = response.verdict_color || VERDICT_COLORS[verdict] || '#4A4A4A';
  var score = typeof response.score === 'number' ? response.score : 0;
  var rawScore = typeof response.raw_score === 'number' ? response.raw_score : score;
  var categoryBreakdown = response.category_breakdown || {};
  var signals = response.signals || [];

  var topSection = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText(formatScore(score)) + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText('Verdict: ') + coloredDot(verdictColor) + ' ' + ltrText(verdict) + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText(buildDisplaySummary(verdict, categoryBreakdown, signals))
    ));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('MailWatch Tower Analysis')
      .setSubtitle('Explainable email risk assessment'))
    .addSection(topSection)
    .addSection(buildLegendSection())
    .addSection(buildDetectedSignalsSection(signals))
    .addSection(buildRecommendationsSection(response.recommendations || [], verdict))
    .addSection(buildTechnicalBreakdownSection(categoryBreakdown, rawScore, score))
    .addSection(buildLimitationsSection(response.limitations || []))
    .build();
}

function buildErrorCard(message, details) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText(message || 'Analysis unavailable') + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('MailWatch Tower could not reach the backend service.')
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Check that BACKEND_BASE_URL in Config.gs points to a public HTTPS backend URL.')
    ));

  if (details) {
    section.addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText('Technical details') + '</b>'
    ));
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText(truncateText(details, 600))
    ));
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Analysis unavailable')
      .setSubtitle(APP_NAME))
    .addSection(section)
    .build();
}

function buildHealthCard(healthResponse) {
  var status = healthResponse && healthResponse.status ? String(healthResponse.status).toUpperCase() : 'UNKNOWN';
  var service = healthResponse && healthResponse.service ? healthResponse.service : 'Backend service';
  var statusColor = status === 'OK' ? '#188038' : '#4A4A4A';
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText('Backend status: ') + coloredDot(statusColor) + ' ' + ltrText(status) + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Service: ' + service)
    ));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Backend Health')
      .setSubtitle(APP_NAME))
    .addSection(section)
    .build();
}

function buildLegendSection() {
  var section = CardService.newCardSection()
    .setHeader('Signal legend')
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Signal colors show what type of risk was detected.')
    ));
  var orderedCategories = ['sender', 'links', 'attachments', 'content', 'headers', 'metadata'];

  orderedCategories.forEach(function(category) {
    section.addWidget(CardService.newTextParagraph().setText(
      coloredDot(CATEGORY_COLORS[category]) + ' ' + ltrText(CATEGORY_LABELS[category])
    ));
  });

  return section;
}

function buildDetectedSignalsSection(signals) {
  var section = CardService.newCardSection().setHeader('Detected signals');
  if (!signals || signals.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('No major malicious-email indicators were detected in this message.')
    ));
    return section;
  }

  var maxSignals = 12;
  signals.slice(0, maxSignals).forEach(function(signal) {
    section.addWidget(CardService.newTextParagraph().setText(
      coloredDot(signal.category_color) + ' <b>' + ltrText(formatSignalTitle(signal)) + '</b>'
    ));
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText(formatSignalMeta(signal))
    ));
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText(truncateText(signal.explanation, 280))
    ));
  });

  if (signals.length > maxSignals) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('Showing top detected signals.')
    ));
  }

  return section;
}

function buildRecommendationsSection(recommendations, verdict) {
  var section = CardService.newCardSection().setHeader('Recommended actions');
  var displayRecommendations = polishedRecommendations(recommendations, verdict);

  displayRecommendations.forEach(function(recommendation) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('- ' + recommendation)
    ));
  });

  return section;
}

function buildTechnicalBreakdownSection(categoryBreakdown, rawScore, score) {
  var section = CardService.newCardSection().setHeader('Technical breakdown');
  var orderedCategories = ['sender', 'links', 'attachments', 'content', 'headers', 'metadata'];

  orderedCategories.forEach(function(category) {
    var label = CATEGORY_LABELS[category];
    var points = categoryBreakdown && categoryBreakdown[category] ? categoryBreakdown[category] : 0;
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText(formatBreakdownLine(label, points))
    ));
  });

  section.addWidget(CardService.newTextParagraph().setText(
    ltrText(formatBreakdownLine('Raw score', rawScore))
  ));
  section.addWidget(CardService.newTextParagraph().setText(
    ltrText(formatFinalScore(score))
  ));

  return section;
}

function buildLimitationsSection(limitations) {
  var section = CardService.newCardSection().setHeader('Analysis limitations');
  var displayedLimitations = [
    'MailWatch Tower does not open attachments or visit links.',
    'The score is based on detected risk indicators, not definitive malware confirmation.',
    'Legitimate messages can still contain suspicious-looking patterns.',
  ];

  (limitations || []).forEach(function(limitation) {
    if (isUsefulBackendLimitation(limitation, displayedLimitations)) {
      displayedLimitations.push(limitation);
    }
  });

  displayedLimitations.forEach(function(limitation) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('- ' + limitation)
    ));
  });

  return section;
}

function isUsefulBackendLimitation(limitation, displayedLimitations) {
  if (!limitation || displayedLimitations.indexOf(limitation) !== -1) {
    return false;
  }
  var normalized = String(limitation).toLowerCase();
  if (normalized.indexOf('the score is based on risk indicators') === 0) {
    return false;
  }
  return true;
}

function buildDisplaySummary(verdict, categoryBreakdown, signals) {
  var detectedCategories = detectedCategoryLabels(categoryBreakdown, signals);
  if (verdict === 'Safe') {
    return 'No major malicious-email indicators were detected in this message.';
  }
  if (verdict === 'Dangerous') {
    return 'This message was marked as Dangerous because multiple high-risk indicators were found across ' +
      joinReadableList(detectedCategories) + '.';
  }
  if (detectedCategories.length > 0) {
    return 'This message was marked as ' + verdict + ' because risk indicators were found across ' +
      joinReadableList(detectedCategories) + '.';
  }
  return 'This message was marked as ' + verdict + ' based on detected risk indicators. Review before taking action.';
}

function detectedCategoryLabels(categoryBreakdown, signals) {
  var orderedCategories = ['sender', 'links', 'attachments', 'content', 'headers', 'metadata'];
  var labels = [];
  orderedCategories.forEach(function(category) {
    var hasBreakdownPoints = categoryBreakdown && categoryBreakdown[category] > 0;
    var hasSignal = (signals || []).some(function(signal) {
      return signal.category === category;
    });
    if (hasBreakdownPoints || hasSignal) {
      labels.push(CATEGORY_LABELS[category]);
    }
  });
  return labels;
}

function polishedRecommendations(recommendations, verdict) {
  if (verdict === 'Dangerous' || verdict === 'High Risk') {
    return [
      'Do not click links or open attachments.',
      'Verify the request through a separate trusted channel.',
      'Report the message using your organization\'s phishing reporting process.',
    ];
  }
  if (verdict === 'Suspicious') {
    return [
      'Review the highlighted indicators before taking action.',
      'Verify the sender through a trusted channel.',
      'Avoid clicking links unless the request is expected.',
    ];
  }
  if (verdict === 'Safe' || verdict === 'Low Risk') {
    return [
      'No immediate action is required based on detected indicators.',
      'Continue to verify unexpected requests through normal channels.',
    ];
  }
  return (recommendations && recommendations.length) ? recommendations : [
    'Review the highlighted indicators before taking action.',
  ];
}

function joinReadableList(values) {
  if (!values || values.length === 0) {
    return 'the analyzed message fields';
  }
  if (values.length === 1) {
    return values[0];
  }
  if (values.length === 2) {
    return values[0] + ' and ' + values[1];
  }
  return values.slice(0, -1).join(', ') + ', and ' + values[values.length - 1];
}

function ltrText(value) {
  return LRM + safeText(value) + LRM;
}

function formatScore(score) {
  return 'Score: ' + numericText(score) + ' out of 100';
}

function formatFinalScore(score) {
  return 'Final score: ' + numericText(score) + ' out of 100';
}

function formatSignalTitle(signal) {
  return signal && signal.name ? signal.name : 'Detected signal';
}

function formatSignalMeta(signal) {
  var points = signal && signal.points !== undefined ? signal.points : 0;
  var severity = signal && signal.severity ? titleCase(signal.severity) : 'Unknown';
  return 'Points: +' + numericText(points) + ' | Severity: ' + severity;
}

function formatBreakdownLine(label, value) {
  return label + ': ' + numericText(value);
}

function coloredDot(hexColor) {
  var color = /^#[0-9A-Fa-f]{6}$/.test(hexColor || '') ? hexColor : '#4A4A4A';
  return LRM + '<font color="' + color + '"><b>' + LARGE_DOT + '</b></font>' + LRM;
}

function titleCase(value) {
  var text = String(value || '').toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function numericText(value) {
  if (value === null || value === undefined || value === '') {
    return '0';
  }
  return String(value);
}

function safeText(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function truncateText(value, maxLength) {
  var text = safeText(value);
  var limit = maxLength || 300;
  if (text.length <= limit) {
    return text;
  }
  return text.slice(0, Math.max(0, limit - 3)) + '...';
}

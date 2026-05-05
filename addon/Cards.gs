/**
 * CardService rendering for the MailWatch Tower Gmail Add-on.
 */

function buildAnalysisResultCard(response) {
  var verdict = safeText(response.verdict);
  var verdictColor = response.verdict_color || VERDICT_COLORS[verdict] || '#4A4A4A';
  var score = typeof response.score === 'number' ? response.score : 0;
  var rawScore = typeof response.raw_score === 'number' ? response.raw_score : score;

  var topSection = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Score')
      .setText(String(score) + ' / 100'))
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText(coloredDot(verdictColor) + ' ' + verdict))
    .addWidget(CardService.newTextParagraph().setText(safeText(response.summary)));

  var builder = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('MailWatch Tower Analysis')
      .setSubtitle('Category colors show signal type. Verdict color shows overall severity.'))
    .addSection(topSection)
    .addSection(buildLegendSection())
    .addSection(buildDetectedSignalsSection(response.signals || []))
    .addSection(buildRecommendationsSection(response.recommendations || []))
    .addSection(buildTechnicalBreakdownSection(response.category_breakdown || {}, rawScore, score))
    .addSection(buildLimitationsSection(response.limitations || []));

  return builder.build();
}

function buildErrorCard(message, details) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      safeText(message || 'Analysis unavailable')
    ))
    .addWidget(CardService.newTextParagraph().setText(
      'MailWatch Tower could not reach the backend service.'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      'Check that BACKEND_BASE_URL in Config.gs points to a public HTTPS backend URL.'
    ));

  if (details) {
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel('Technical details')
      .setText(truncateText(details, 600)));
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Analysis unavailable')
      .setSubtitle(APP_NAME))
    .addSection(section)
    .build();
}

function buildHealthCard(healthResponse) {
  var status = healthResponse && healthResponse.status ? healthResponse.status : 'unknown';
  var service = healthResponse && healthResponse.service ? healthResponse.service : 'Backend service';
  var section = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Status')
      .setText(coloredDot('#188038') + ' ' + safeText(status)))
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Service')
      .setText(safeText(service)));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Backend Health')
      .setSubtitle(APP_NAME))
    .addSection(section)
    .build();
}

function buildLegendSection() {
  var section = CardService.newCardSection().setHeader('Signal legend');
  var orderedCategories = ['sender', 'links', 'attachments', 'content', 'headers', 'metadata'];

  orderedCategories.forEach(function(category) {
    section.addWidget(CardService.newTextParagraph().setText(
      coloredDot(CATEGORY_COLORS[category]) + ' ' + CATEGORY_LABELS[category]
    ));
  });

  return section;
}

function buildDetectedSignalsSection(signals) {
  var section = CardService.newCardSection().setHeader('Detected signals');
  if (!signals || signals.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText('No strong risk indicators were found.'));
    return section;
  }

  var maxSignals = 12;
  signals.slice(0, maxSignals).forEach(function(signal) {
    section.addWidget(CardService.newTextParagraph().setText(
      coloredDot(signal.category_color) + ' ' +
      '<b>' + safeText(signal.name) + '</b> - +' + safeText(signal.points) +
      ' - ' + safeText(signal.severity)
    ));
    section.addWidget(CardService.newTextParagraph().setText(
      truncateText(signal.explanation, 260)
    ));
  });

  if (signals.length > maxSignals) {
    section.addWidget(CardService.newTextParagraph().setText('Showing top detected signals.'));
  }

  return section;
}

function buildRecommendationsSection(recommendations) {
  var section = CardService.newCardSection().setHeader('Recommended actions');
  if (!recommendations || recommendations.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText('No additional action is recommended.'));
    return section;
  }

  recommendations.forEach(function(recommendation) {
    section.addWidget(CardService.newTextParagraph().setText('- ' + safeText(recommendation)));
  });

  return section;
}

function buildTechnicalBreakdownSection(categoryBreakdown, rawScore, score) {
  var section = CardService.newCardSection().setHeader('Technical breakdown');
  var orderedCategories = ['sender', 'links', 'attachments', 'content', 'headers', 'metadata'];

  orderedCategories.forEach(function(category) {
    var label = CATEGORY_LABELS[category];
    var points = categoryBreakdown && categoryBreakdown[category] ? categoryBreakdown[category] : 0;
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel(label)
      .setText(String(points)));
  });

  section.addWidget(CardService.newDecoratedText()
    .setTopLabel('Raw score')
    .setText(String(rawScore)));
  section.addWidget(CardService.newDecoratedText()
    .setTopLabel('Final score')
    .setText(String(score) + ' / 100'));

  return section;
}

function buildLimitationsSection(limitations) {
  var section = CardService.newCardSection().setHeader('Limitations');
  var displayedLimitations = limitations && limitations.length ? limitations : [
    'MailWatch Tower does not open attachments or visit links.',
    'The score is based on risk indicators, not definitive malware confirmation.',
  ];

  displayedLimitations.forEach(function(limitation) {
    section.addWidget(CardService.newTextParagraph().setText('- ' + safeText(limitation)));
  });

  return section;
}

function coloredDot(hexColor) {
  var color = hexColor || '#4A4A4A';
  return '<font color="' + color + '">●</font>';
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

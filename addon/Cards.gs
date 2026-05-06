/**
 * CardService rendering for the MailWatch Tower Gmail Add-on.
 */

var LRM = '\u200E';
var LARGE_DOT = '\u2B24';

function buildMainAnalysisCard(analysis, confirmationMessage) {
  analysis = analysis || {};
  var verdict = analysis.verdict || 'Unknown';
  var verdictColor = VERDICT_COLORS[verdict] || '#4A4A4A';
  var finalScore = valueOrZero_(analysis.final_score !== undefined ? analysis.final_score : analysis.score);
  var baseScore = valueOrZero_(analysis.base_score !== undefined ? analysis.base_score : analysis.raw_score);

  var topSection = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText('Verdict: ') + coloredDot(verdictColor) + ' ' + ltrText(verdict) + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText('Final score: ' + finalScore + ' out of 100') + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Base score before feedback: ' + baseScore)
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText(analysis.summary || 'Risk indicators were analyzed for the opened message.')
    ));

  if (confirmationMessage) {
    topSection.addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText(confirmationMessage) + '</b>'
    ));
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(APP_NAME)
      .setSubtitle('Explainable email risk assessment'))
    .addSection(topSection)
    .addSection(buildCategorySummarySection(analysis))
    .addSection(buildRecommendedActionsSection(analysis.recommended_actions || analysis.recommendations || []))
    .addSection(buildAppliedAdjustmentsSection(analysis.applied_adjustments || []))
    .addSection(buildMainControlsSection())
    .build();
}

function buildAnalysisResultCard(response) {
  return buildMainAnalysisCard(response);
}

function buildCategorySummarySection(analysis) {
  var section = CardService.newCardSection().setHeader('Category scores');
  var categories = analysis.categories || {};

  CATEGORY_ORDER.forEach(function(categoryKey) {
    var category = categories[categoryKey];
    if (!category && categoryKey === 'user_feedback') {
      return;
    }
    var label = category && category.title ? category.title : CATEGORY_LABELS[categoryKey];
    var score = category ? valueOrZero_(category.score) : valueOrZero_((analysis.category_scores || {})[categoryKey]);
    var maxScore = category ? valueOrZero_(category.max_score) : '';
    var scoreText = maxScore !== '' ? score + ' out of ' + maxScore : String(score);

    section.addWidget(CardService.newDecoratedText()
      .setTopLabel(label)
      .setText(ltrText(scoreText))
      .setBottomLabel(category && category.short_summary ? truncateText(category.short_summary, 120) : ''));

    section.addWidget(buildCategoryButton_(categoryKey));
  });

  return section;
}

function buildCategoryButton_(categoryKey) {
  return CardService.newTextButton()
    .setText(categoryButtonLabel_(categoryKey))
    .setOnClickAction(CardService.newAction()
      .setFunctionName('buildCategoryDrilldownCard')
      .setParameters({ category_key: categoryKey }));
}

function categoryButtonLabel_(categoryKey) {
  return {
    sender_auth: 'Sender Advanced Details',
    links: 'Link Advanced Details',
    attachments: 'Attachment Advanced Details',
    content: 'Content Advanced Details',
    external_intel: 'External Intel Details',
    user_feedback: 'Feedback Advanced Details',
  }[categoryKey] || 'Advanced Details';
}

function buildCategoryCard(analysis, categoryKey) {
  analysis = analysis || {};
  var category = (analysis.categories || {})[categoryKey];
  if (!category) {
    return buildErrorCard('Details unavailable', 'The selected category was not returned by the backend.');
  }

  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText(category.title) + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Score: ' + valueOrZero_(category.score) + ' out of ' + valueOrZero_(category.max_score))
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Status: ' + titleCase(category.status || 'not_available'))
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText(category.short_summary || 'No summary was provided for this category.')
    ));

  var checks = category.checks || [];
  if (checks.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('No checks were returned for this category.')
    ));
  } else {
    checks.forEach(function(check) {
      section.addWidget(buildCheckWidget_(check));
    });
  }

  var feedbackSection = buildFeedbackActionsSection(category.feedback_actions || [], analysis.message_fingerprint);

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(category.title)
      .setSubtitle(APP_NAME))
    .addSection(section)
    .addSection(feedbackSection)
    .addSection(buildDrilldownControlsSection())
    .build();
}

function buildCheckWidget_(check) {
  var points = valueOrZero_(check.points);
  var title = check.name || 'Check';
  var result = titleCase(check.result || 'not_available');
  var text = '<b>' + ltrText(title) + '</b><br>' +
    ltrText('Result: ' + result + ' | Points: +' + points) + '<br>' +
    ltrText(check.explanation || 'No explanation provided.');
  if (check.evidence_summary) {
    text += '<br>' + ltrText('Evidence: ' + check.evidence_summary);
  }
  return CardService.newTextParagraph().setText(text);
}

function buildFeedbackActionsSection(actions, messageFingerprint) {
  var section = CardService.newCardSection().setHeader('Feedback actions');
  if (!actions || actions.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('No feedback actions are available for this category.')
    ));
    return section;
  }

  actions.slice(0, 8).forEach(function(action) {
    section.addWidget(buildFeedbackButton_(action, messageFingerprint));
  });

  return section;
}

function buildFeedbackButton_(feedbackAction, messageFingerprint) {
  var isTrusted = feedbackAction.action === 'mark_trusted';
  var label = isTrusted ? 'trusted' : 'malicious';
  var button = CardService.newTextButton()
    .setText(feedbackAction.label)
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setBackgroundColor(isTrusted ? '#188038' : '#D93025')
    .setOnClickAction(CardService.newAction()
      .setFunctionName('submitFeedback')
      .setParameters({
        message_fingerprint: messageFingerprint || '',
        indicator_type: feedbackAction.indicator_type || '',
        indicator_value: feedbackAction.indicator_value || '',
        label: label,
        source_category: feedbackAction.source_category || '',
      }));
  return button;
}

function buildRecommendedActionsSection(recommendations) {
  var section = CardService.newCardSection().setHeader('Recommended actions');
  if (!recommendations || recommendations.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('No immediate action is required based on detected indicators.')
    ));
    return section;
  }
  recommendations.forEach(function(recommendation) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('- ' + recommendation)
    ));
  });
  return section;
}

function buildAppliedAdjustmentsSection(adjustments) {
  var section = CardService.newCardSection().setHeader('Applied adjustments');
  if (!adjustments || adjustments.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('No user feedback adjustments were applied.')
    ));
    return section;
  }
  adjustments.forEach(function(adjustment) {
    var points = adjustment.points > 0 ? '+' + adjustment.points : String(adjustment.points);
    section.addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText(points + ' | ' + titleCase(String(adjustment.type || '').replace(/_/g, ' '))) + '</b>'
    ));
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText(adjustment.explanation || '')
    ));
  });
  return section;
}

function buildMainControlsSection() {
  return CardService.newCardSection()
    .addWidget(CardService.newTextButton()
      .setText('Refresh Analysis')
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor('#0B3D91')
      .setOnClickAction(CardService.newAction().setFunctionName('refreshAnalysisAction')));
}

function buildDrilldownControlsSection() {
  return CardService.newCardSection()
    .addWidget(CardService.newTextButton()
      .setText('Back to Analysis')
      .setOnClickAction(CardService.newAction().setFunctionName('backToMainCardAction')))
    .addWidget(CardService.newTextButton()
      .setText('Refresh Analysis')
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor('#0B3D91')
      .setOnClickAction(CardService.newAction().setFunctionName('refreshAnalysisAction')));
}

function backToMainCardAction(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

function buildErrorCard(message, details) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText(message || 'Analysis unavailable') + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('MailWatch Tower could not complete the request.')
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Check BACKEND_BASE_URL / tunnel URL and backend /health.')
    ));

  if (details) {
    section.addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText('Technical details') + '</b>'
    ));
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText(truncateText(details, 600))
    ));
  }

  section.addWidget(CardService.newTextButton()
    .setText('Retry Analysis')
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setBackgroundColor('#0B3D91')
    .setOnClickAction(CardService.newAction().setFunctionName('buildRetryAnalysisAction')));

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
  var version = healthResponse && healthResponse.version ? healthResponse.version : 'unknown';
  var statusColor = status === 'OK' ? '#188038' : '#4A4A4A';
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText('Backend status: ') + coloredDot(statusColor) + ' ' + ltrText(status) + '</b>'
    ))
    .addWidget(CardService.newTextParagraph().setText(ltrText('Service: ' + service)))
    .addWidget(CardService.newTextParagraph().setText(ltrText('Version: ' + version)));

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
  CATEGORY_ORDER.forEach(function(categoryKey) {
    section.addWidget(CardService.newTextParagraph().setText(
      coloredDot(CATEGORY_COLORS[categoryKey]) + ' ' + ltrText(CATEGORY_LABELS[categoryKey])
    ));
  });
  return section;
}

function coloredDot(hexColor) {
  var color = /^#[0-9A-Fa-f]{6}$/.test(hexColor || '') ? hexColor : '#4A4A4A';
  return LRM + '<font color="' + color + '"><b>' + LARGE_DOT + '</b></font>' + LRM;
}

function ltrText(value) {
  return LRM + safeText(value) + LRM;
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

function titleCase(value) {
  return String(value || '')
    .split(/[\s_]+/)
    .filter(function(part) { return part.length > 0; })
    .map(function(part) { return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase(); })
    .join(' ');
}

function valueOrZero_(value) {
  return value === null || value === undefined || value === '' ? 0 : value;
}

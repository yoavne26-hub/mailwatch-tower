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
    .addSection(buildSignalCategoryLegendSection())
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
    var label = CATEGORY_LABELS[categoryKey] || (category && category.title) || categoryKey;
    var score = category ? valueOrZero_(category.score) : valueOrZero_((analysis.category_scores || {})[categoryKey]);
    var maxScore = category ? valueOrZero_(category.max_score) : '';
    var scoreText = maxScore !== '' ? score + ' out of ' + maxScore : String(score);

    section.addWidget(CardService.newTextParagraph().setText(
      coloredDot(CATEGORY_COLORS[categoryKey]) + ' <b>' + ltrText(label) + '</b>'
    ));
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('Score: ' + scoreText)
    ));
    if (category && category.short_summary) {
      section.addWidget(CardService.newTextParagraph().setText(
        ltrText(truncateText(category.short_summary, 140))
      ));
    }

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

function buildCategoryCard(analysis, categoryKey, noticeMessage) {
  analysis = analysis || {};
  var category = (analysis.categories || {})[categoryKey];
  if (!category) {
    return buildErrorCard('Details unavailable', 'The selected category was not returned by the backend.');
  }

  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      coloredDot(CATEGORY_COLORS[categoryKey]) + ' <b>' + ltrText(CATEGORY_LABELS[categoryKey] || category.title) + '</b>'
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

  if (noticeMessage) {
    section.addWidget(CardService.newTextParagraph().setText(
      '<b>' + ltrText(noticeMessage) + '</b>'
    ));
  }

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

  var pendingFeedback = loadPendingFeedback_(analysis.message_fingerprint);
  var feedbackSection = buildFeedbackActionsSection(
    category.feedback_actions || [],
    analysis.message_fingerprint,
    categoryKey,
    pendingFeedback
  );

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(category.title)
      .setSubtitle(APP_NAME))
    .addSection(section)
    .addSection(feedbackSection)
    .addSection(buildDrilldownControlsSection())
    .build();
}

function buildSignalCategoryLegendSection() {
  var section = CardService.newCardSection()
    .setHeader('Signal category colors')
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Category color = signal type. Verdict color = overall severity.')
    ));

  SIGNAL_LEGEND_ITEMS.forEach(function(item) {
    section.addWidget(CardService.newTextParagraph().setText(
      coloredDot(item.color) + ' ' + ltrText(item.label)
    ));
  });

  return section;
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

function buildFeedbackActionsSection(actions, messageFingerprint, categoryKey, pendingFeedback) {
  var section = CardService.newCardSection().setHeader('Feedback actions');
  var displayActions = dedupeFeedbackActions_(actions || []);
  if (displayActions.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText(
      ltrText('No feedback actions are available for this category.')
    ));
    return section;
  }

  section.addWidget(CardService.newTextParagraph().setText(
    ltrText('Selections are staged. Press Refresh Analysis to apply them.')
  ));

  var currentGroup = null;
  displayActions.slice(0, 12).forEach(function(action) {
    var group = feedbackTargetDisplay_(action);
    if (group && group !== currentGroup) {
      currentGroup = group;
      section.addWidget(CardService.newTextParagraph().setText(
        '<b>' + ltrText(group) + '</b>'
      ));
    }
    if (isFeedbackPending_(pendingFeedback, action)) {
      section.addWidget(CardService.newTextParagraph().setText(
        coloredDot(SELECTED_FEEDBACK_COLOR) + ' <b>' + ltrText('Selected pending action') + '</b>'
      ));
    }
    section.addWidget(buildFeedbackButton_(action, messageFingerprint, categoryKey, pendingFeedback));
  });

  return section;
}

function buildFeedbackButton_(feedbackAction, messageFingerprint, categoryKey, pendingFeedback) {
  var isTrusted = feedbackAction.action === 'mark_trusted';
  var label = isTrusted ? 'trusted' : 'malicious';
  var selected = isFeedbackPending_(pendingFeedback, feedbackAction);
  var buttonLabel = (selected ? '\u2713 ' : '') + feedbackButtonLabel_(feedbackAction);
  var button = CardService.newTextButton()
    .setText(buttonLabel)
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setBackgroundColor(isTrusted ? '#188038' : '#D93025')
    .setOnClickAction(CardService.newAction()
      .setFunctionName('submitFeedback')
      .setParameters({
        message_fingerprint: messageFingerprint || '',
        indicator_type: feedbackAction.indicator_type || '',
        indicator_value: feedbackAction.indicator_value || '',
        label: label,
        action: feedbackAction.action || '',
        source_category: feedbackAction.source_category || '',
        category_key: categoryKey || feedbackAction.source_category || '',
      }));
  return button;
}

function dedupeFeedbackActions_(actions) {
  var unique = {};
  var deduped = [];
  actions.forEach(function(action) {
    var normalizedValue = normalizeFeedbackActionValue_(action);
    var key = [
      action.action || '',
      action.indicator_type || '',
      normalizedValue,
      action.source_category || '',
    ].join('|');
    if (!unique[key]) {
      unique[key] = true;
      var cloned = {};
      Object.keys(action || {}).forEach(function(field) {
        cloned[field] = action[field];
      });
      cloned.indicator_value = action.indicator_value || '';
      deduped.push(cloned);
    }
  });
  return deduped;
}

function feedbackButtonLabel_(action) {
  var target = feedbackTargetDisplay_(action);
  var type = action.indicator_type || '';
  var isTrusted = action.action === 'mark_trusted';
  if (type === 'url') {
    return (isTrusted ? 'Trust URL: ' : 'Mark URL malicious: ') + target;
  }
  if (type === 'link_domain' || type === 'sender_domain' || type === 'reply_to_domain') {
    return (isTrusted ? 'Trust domain: ' : 'Mark domain malicious: ') + target;
  }
  if (type === 'sender_email') {
    return (isTrusted ? 'Trust sender: ' : 'Mark sender malicious: ') + truncateMiddle_(target, 42);
  }
  if (type === 'attachment_extension') {
    return 'Mark .' + target.replace(/^\./, '') + ' malicious';
  }
  if (type === 'attachment_filename_pattern') {
    return 'Mark filename pattern malicious: ' + truncateMiddle_(target, 34);
  }
  return action.label || (isTrusted ? 'Trust indicator' : 'Mark indicator malicious');
}

function feedbackTargetDisplay_(action) {
  var type = action.indicator_type || '';
  var value = String(action.indicator_value || '');
  if (type === 'url') {
    return displayDomainFromUrl_(value) || truncateMiddle_(stripUrlNoise_(value), 40);
  }
  if (type === 'link_domain' || type === 'sender_domain' || type === 'reply_to_domain') {
    return normalizeDisplayDomain_(value);
  }
  if (type === 'attachment_extension') {
    return value.replace(/^\./, '').toLowerCase();
  }
  return truncateMiddle_(value, 48);
}

function normalizeFeedbackActionValue_(action) {
  var type = action.indicator_type || '';
  var value = String(action.indicator_value || '').toLowerCase().trim();
  if (type === 'url') {
    return stripUrlNoise_(value);
  }
  return value.replace(/^https?:\/\//, '').replace(/\/+$/, '');
}

function displayDomainFromUrl_(value) {
  var match = String(value || '').match(/^https?:\/\/([^\/?#]+)/i);
  if (!match) {
    return '';
  }
  return normalizeDisplayDomain_(match[1]);
}

function normalizeDisplayDomain_(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0];
}

function stripUrlNoise_(value) {
  return String(value || '').split('#')[0].split('?')[0].replace(/\/+$/, '');
}

function truncateMiddle_(value, maxLength) {
  var text = String(value || '');
  var limit = maxLength || 40;
  if (text.length <= limit) {
    return text;
  }
  var keep = Math.floor((limit - 3) / 2);
  return text.slice(0, keep) + '...' + text.slice(text.length - keep);
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
  SIGNAL_LEGEND_ITEMS.forEach(function(item) {
    section.addWidget(CardService.newTextParagraph().setText(
      coloredDot(item.color) + ' ' + ltrText(item.label)
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

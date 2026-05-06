/**
 * MailWatch Tower Gmail Add-on entrypoints and message extraction.
 */

function buildHomeCard(e) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('MailWatch Tower analyzes the opened email for malicious-email risk indicators and explains the score.')
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('Open an email to analyze sender identity, links, attachments, content, external intelligence, and feedback indicators.')
    ))
    .addWidget(CardService.newTextParagraph().setText(
      ltrText('MailWatch Tower sends only the current message fields needed for analysis. It does not send attachment bytes, open attachments, or visit links.')
    ))
    .addWidget(CardService.newTextButton()
      .setText('Check Backend Health')
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor('#0B3D91')
      .setOnClickAction(CardService.newAction().setFunctionName('checkBackendHealthAction')));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(APP_NAME)
      .setSubtitle('Explainable email risk analysis for Gmail'))
    .addSection(section)
    .build();
}

function buildMessageAnalysisCard(e) {
  return analyzeCurrentMessage(e);
}

function buildAddOn(e) {
  return analyzeCurrentMessage(e);
}

function getContextualAddOn(e) {
  return analyzeCurrentMessage(e);
}

function analyzeCurrentMessage(e) {
  try {
    var payload = extractCurrentMessagePayload(e);
    var analysis = analyzeEmail(payload);
    cacheAnalysis_(analysis);
    return buildMainAnalysisCard(analysis);
  } catch (error) {
    return buildErrorCard('Analysis unavailable', friendlyError_(error));
  }
}

function refreshAnalysisAction(e) {
  var applyingFeedback = false;
  var feedbackSubmitted = false;
  try {
    var payload = extractCurrentMessagePayload(e);
    var pendingFeedback = loadPendingFeedback_(payload.message_fingerprint);
    if (pendingFeedback.length > 0) {
      applyingFeedback = true;
      submitPendingFeedbackActions_(pendingFeedback, payload.message_fingerprint);
      feedbackSubmitted = true;
      clearPendingFeedback_(payload.message_fingerprint);
    }

    var analysis = analyzeEmail(payload);
    cacheAnalysis_(analysis);
    var confirmation = feedbackSubmitted ? 'Feedback applied. Analysis refreshed.' : 'Analysis refreshed.';
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(buildMainAnalysisCard(analysis, confirmation)))
      .build();
  } catch (error) {
    var message = feedbackSubmitted ? 'Feedback was saved, but analysis refresh failed.' :
      (applyingFeedback ? 'Could not apply feedback.' : 'Refresh failed');
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildErrorCard(message, friendlyError_(error))))
      .build();
  }
}

function buildCategoryDrilldownCard(e) {
  try {
    var parameters = getActionParameters_(e);
    var categoryKey = parameters.category_key;
    var payload = extractCurrentMessagePayload(e);
    var analysis = analyzeEmail(payload);
    cacheAnalysis_(analysis);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildCategoryCard(analysis, categoryKey)))
      .build();
  } catch (error) {
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildErrorCard('Details unavailable', friendlyError_(error))))
      .build();
  }
}

function submitFeedback(e) {
  try {
    var parameters = getActionParameters_(e);
    var payload = extractCurrentMessagePayload(e);
    var messageFingerprint = parameters.message_fingerprint || payload.message_fingerprint;
    var categoryKey = parameters.category_key || parameters.source_category || '';
    var feedbackPayload = {
      action: parameters.action,
      message_fingerprint: messageFingerprint,
      indicator_type: parameters.indicator_type,
      indicator_value: parameters.indicator_value,
      label: parameters.label,
      source_category: parameters.source_category,
    };

    togglePendingFeedback_(messageFingerprint, feedbackPayload);
    var cachedAnalysis = getCachedAnalysis_(messageFingerprint);
    if (!cachedAnalysis) {
      throw new Error('The analysis details cache expired. Press Refresh Analysis, then open the category again.');
    }

    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(
        buildCategoryCard(cachedAnalysis, categoryKey, 'Feedback selection updated. Press Refresh Analysis to apply it.')
      ))
      .build();
  } catch (error) {
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildErrorCard('Feedback selection failed', friendlyError_(error))))
      .build();
  }
}

function submitPendingFeedbackActions_(pendingFeedback, messageFingerprint) {
  pendingFeedback.forEach(function(action) {
    submitFeedbackToBackend({
      message_fingerprint: action.message_fingerprint || messageFingerprint,
      indicator_type: action.indicator_type || '',
      indicator_value: action.indicator_value || '',
      label: action.label || '',
      source_category: action.source_category || '',
    });
  });
}

function buildRetryAnalysisAction(e) {
  return refreshAnalysisAction(e);
}

function extractCurrentMessagePayload(e) {
  var gmailContext = validateGmailContext_(e);
  GmailApp.setCurrentMessageAccessToken(gmailContext.accessToken);
  var message = GmailApp.getMessageById(gmailContext.messageId);
  var fromHeader = cleanString_(message.getFrom());
  var parsedSender = parseSenderHeader_(fromHeader);
  var plainBody = cleanString_(message.getPlainBody());
  var bodyText = truncatePlainText_(plainBody, MAX_BODY_CHARS);
  var attachments = extractAttachmentMetadata_(message);

  return {
    message_id: cleanString_(message.getId()),
    message_fingerprint: buildMessageFingerprint_(message, parsedSender.email, bodyText),
    sender_email: parsedSender.email,
    sender_display_name: parsedSender.displayName,
    from_header: fromHeader,
    reply_to: cleanString_(message.getReplyTo()),
    return_path: getHeaderSafely_(message, 'Return-Path'),
    subject: truncatePlainText_(message.getSubject(), 500),
    body_text: bodyText,
    urls: extractUrlsFromText_(bodyText),
    attachments: attachments,
    headers: {
      authentication_results: getHeaderSafely_(message, 'Authentication-Results'),
      spf: getHeaderSafely_(message, 'Received-SPF'),
      dkim: extractAuthToken_(getHeaderSafely_(message, 'Authentication-Results'), 'dkim'),
      dmarc: extractAuthToken_(getHeaderSafely_(message, 'Authentication-Results'), 'dmarc'),
    },
  };
}

function validateGmailContext_(e) {
  if (!e || !e.gmail || !e.gmail.accessToken || !e.gmail.messageId) {
    throw new Error('The Gmail message context is unavailable. Open a message and try again.');
  }
  return e.gmail;
}

function extractAttachmentMetadata_(message) {
  var attachments = message.getAttachments({
    includeInlineImages: false,
    includeAttachments: true,
  }) || [];

  return attachments.slice(0, MAX_ATTACHMENTS).map(function(attachment) {
    return {
      filename: cleanString_(attachment.getName()),
      mime_type: cleanString_(attachment.getContentType()),
      size_bytes: getAttachmentSizeSafely_(attachment),
    };
  });
}

function getAttachmentSizeSafely_(attachment) {
  try {
    if (attachment && typeof attachment.getSize === 'function') {
      return attachment.getSize();
    }
  } catch (error) {
    return null;
  }
  return null;
}

function extractUrlsFromText_(text) {
  var value = String(text || '');
  var regex = /https?:\/\/[^\s<>"')]+/gi;
  var urls = [];
  var seen = {};
  var match;
  while ((match = regex.exec(value)) !== null && urls.length < MAX_URLS) {
    var url = trimUrlPunctuation_(match[0]);
    if (seen[url]) {
      continue;
    }
    seen[url] = true;
    urls.push({
      url: url,
      anchor_text: '',
      surrounding_text: surroundingText_(value, match.index, match[0].length),
    });
  }
  return urls;
}

function surroundingText_(text, index, length) {
  var start = Math.max(0, index - 120);
  var end = Math.min(text.length, index + length + 120);
  return truncatePlainText_(text.slice(start, end), 500);
}

function trimUrlPunctuation_(url) {
  return String(url || '').replace(/[.,;:!?]+$/, '');
}

function parseSenderHeader_(fromHeader) {
  var header = String(fromHeader || '').trim();
  var match = header.match(/^(.*)<([^>]+)>$/);
  if (match) {
    return {
      displayName: cleanString_(match[1].replace(/^"|"$/g, '').trim()),
      email: cleanString_(match[2].trim().toLowerCase()),
    };
  }
  var emailMatch = header.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return {
    displayName: emailMatch ? cleanString_(header.replace(emailMatch[0], '').trim()) : '',
    email: emailMatch ? cleanString_(emailMatch[0].toLowerCase()) : '',
  };
}

function getHeaderSafely_(message, headerName) {
  try {
    return cleanString_(message.getHeader(headerName));
  } catch (error) {
    return '';
  }
}

function extractAuthToken_(authHeader, tokenName) {
  var match = String(authHeader || '').match(new RegExp(tokenName + '=([a-zA-Z_]+)', 'i'));
  return match ? match[1].toLowerCase() : '';
}

function buildMessageFingerprint_(message, senderEmail, bodyText) {
  var seed = [
    cleanString_(message.getId()),
    cleanString_(senderEmail),
    cleanString_(message.getSubject()),
    String(bodyText || '').slice(0, 500),
  ].join('|');
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, seed, Utilities.Charset.UTF_8);
  return digest.map(function(byteValue) {
    var normalized = (byteValue + 256) % 256;
    return ('0' + normalized.toString(16)).slice(-2);
  }).join('');
}

function cacheAnalysis_(analysis) {
  if (!analysis || !analysis.message_fingerprint) {
    return;
  }
  CacheService.getUserCache().put(
    cacheKey_(analysis.message_fingerprint),
    JSON.stringify(analysis),
    ANALYSIS_CACHE_SECONDS
  );
}

function getCachedAnalysis_(messageFingerprint) {
  if (!messageFingerprint) {
    return null;
  }
  try {
    var cached = CacheService.getUserCache().get(cacheKey_(messageFingerprint));
    return cached ? JSON.parse(cached) : null;
  } catch (error) {
    Logger.log('Could not read cached analysis: ' + sanitizeLogText_(error.message || error));
    return null;
  }
}

function cacheKey_(messageFingerprint) {
  return 'analysis:' + messageFingerprint;
}

function pendingFeedbackKey_(messageFingerprint) {
  return 'pending-feedback:' + messageFingerprint;
}

function loadPendingFeedback_(messageFingerprint) {
  if (!messageFingerprint) {
    return [];
  }
  try {
    var cached = CacheService.getUserCache().get(pendingFeedbackKey_(messageFingerprint));
    var parsed = cached ? JSON.parse(cached) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    Logger.log('Could not read pending feedback state: ' + sanitizeLogText_(error.message || error));
    return [];
  }
}

function savePendingFeedback_(messageFingerprint, pendingFeedback) {
  if (!messageFingerprint) {
    return;
  }
  CacheService.getUserCache().put(
    pendingFeedbackKey_(messageFingerprint),
    JSON.stringify(pendingFeedback || []),
    PENDING_FEEDBACK_CACHE_SECONDS
  );
}

function clearPendingFeedback_(messageFingerprint) {
  if (!messageFingerprint) {
    return;
  }
  CacheService.getUserCache().remove(pendingFeedbackKey_(messageFingerprint));
}

function togglePendingFeedback_(messageFingerprint, feedbackAction) {
  var pendingFeedback = loadPendingFeedback_(messageFingerprint);
  var selectedKey = pendingFeedbackActionKey_(feedbackAction);
  var conflictKey = pendingFeedbackConflictKey_(feedbackAction);
  var alreadySelected = false;
  var nextPending = [];

  pendingFeedback.forEach(function(existingAction) {
    if (pendingFeedbackActionKey_(existingAction) === selectedKey) {
      alreadySelected = true;
      return;
    }
    if (pendingFeedbackConflictKey_(existingAction) === conflictKey) {
      return;
    }
    nextPending.push(existingAction);
  });

  if (!alreadySelected) {
    nextPending.push({
      action: cleanString_(feedbackAction.action),
      message_fingerprint: messageFingerprint,
      indicator_type: cleanString_(feedbackAction.indicator_type),
      indicator_value: cleanString_(feedbackAction.indicator_value),
      label: cleanString_(feedbackAction.label),
      source_category: cleanString_(feedbackAction.source_category),
    });
  }

  savePendingFeedback_(messageFingerprint, nextPending);
  return nextPending;
}

function pendingFeedbackActionKey_(feedbackAction) {
  return [
    cleanString_(feedbackAction.action),
    cleanString_(feedbackAction.indicator_type),
    normalizePendingIndicatorValue_(feedbackAction.indicator_type, feedbackAction.indicator_value),
    canonicalFeedbackLabel_(feedbackAction),
    cleanString_(feedbackAction.source_category),
  ].join('|');
}

function pendingFeedbackConflictKey_(feedbackAction) {
  return [
    cleanString_(feedbackAction.indicator_type),
    normalizePendingIndicatorValue_(feedbackAction.indicator_type, feedbackAction.indicator_value),
    cleanString_(feedbackAction.source_category),
  ].join('|');
}

function isFeedbackPending_(pendingFeedback, feedbackAction) {
  var selectedKey = pendingFeedbackActionKey_(feedbackAction);
  return (pendingFeedback || []).some(function(existingAction) {
    return pendingFeedbackActionKey_(existingAction) === selectedKey;
  });
}

function normalizePendingIndicatorValue_(indicatorType, value) {
  var type = cleanString_(indicatorType);
  var normalized = cleanString_(value).toLowerCase();
  if (type === 'url') {
    return normalized.split('#')[0].split('?')[0].replace(/\/+$/, '');
  }
  if (type === 'link_domain' || type === 'sender_domain' || type === 'reply_to_domain') {
    return normalized.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
  }
  return normalized.replace(/^https?:\/\//, '').replace(/\/+$/, '');
}

function canonicalFeedbackLabel_(feedbackAction) {
  var label = cleanString_(feedbackAction.label);
  if (label) {
    return label;
  }
  return feedbackAction.action === 'mark_trusted' ? 'trusted' : 'malicious';
}

function getActionParameters_(e) {
  if (e && e.commonEventObject && e.commonEventObject.parameters) {
    return e.commonEventObject.parameters;
  }
  if (e && e.parameters) {
    return e.parameters;
  }
  return {};
}

function cleanString_(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value).trim();
}

function truncatePlainText_(value, maxLength) {
  var text = cleanString_(value);
  var limit = maxLength || MAX_BODY_CHARS;
  if (text.length <= limit) {
    return text;
  }
  return text.slice(0, limit);
}

function friendlyError_(error) {
  var message = error && error.message ? error.message : String(error);
  Logger.log('MailWatch Tower add-on error: ' + sanitizeLogText_(message));
  return message;
}

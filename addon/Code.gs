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
  try {
    var payload = extractCurrentMessagePayload(e);
    var analysis = analyzeEmail(payload);
    cacheAnalysis_(analysis);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(buildMainAnalysisCard(analysis, 'Analysis refreshed.')))
      .build();
  } catch (error) {
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildErrorCard('Refresh failed', friendlyError_(error))))
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
    var feedbackPayload = {
      message_fingerprint: parameters.message_fingerprint || payload.message_fingerprint,
      indicator_type: parameters.indicator_type,
      indicator_value: parameters.indicator_value,
      label: parameters.label,
      source_category: parameters.source_category,
    };

    submitFeedbackToBackend(feedbackPayload);
    var refreshed = analyzeEmail(payload);
    cacheAnalysis_(refreshed);

    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(buildMainAnalysisCard(refreshed, 'Feedback saved. Analysis refreshed.')))
      .build();
  } catch (error) {
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildErrorCard('Feedback was not saved', friendlyError_(error))))
      .build();
  }
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
  var cached = CacheService.getUserCache().get(cacheKey_(messageFingerprint));
  return cached ? JSON.parse(cached) : null;
}

function cacheKey_(messageFingerprint) {
  return 'analysis:' + messageFingerprint;
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

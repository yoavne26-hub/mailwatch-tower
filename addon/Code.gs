/**
 * MailWatch Tower Gmail Add-on entrypoints.
 */

function buildHomeCard(e) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      'Explainable email risk analysis for Gmail.'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      'Open an email to analyze sender, links, attachments, content, and authentication indicators.'
    ))
    .addWidget(CardService.newTextParagraph().setText(
      'MailWatch Tower analyzes the currently opened message only. It does not store emails, open attachments, or visit links.'
    ))
    .addWidget(CardService.newTextButton()
      .setText('Check Backend Health')
      .setOnClickAction(CardService.newAction().setFunctionName('checkBackendHealthAction')));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(APP_NAME)
      .setSubtitle('Explainable email risk analysis for Gmail'))
    .addSection(section)
    .build();
}

function buildMessageAnalysisCard(e) {
  try {
    if (!e || !e.gmail || !e.gmail.accessToken || !e.gmail.messageId) {
      return buildErrorCard(
        'Analysis unavailable',
        'The Gmail contextual trigger did not include current-message access.'
      );
    }

    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    var payload = extractCurrentMessagePayload(e);
    var response = analyzeEmail(payload);
    return buildAnalysisResultCard(response);
  } catch (error) {
    return buildErrorCard('Analysis unavailable', error && error.message ? error.message : String(error));
  }
}

function extractCurrentMessagePayload(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);
  var attachments = message.getAttachments({
    includeInlineImages: false,
    includeAttachments: true,
  });

  return {
    message_id: safeText(message.getId()),
    subject: safeText(message.getSubject()),
    from: safeText(message.getFrom()),
    reply_to: safeText(message.getReplyTo()),
    to: splitRecipients_(message.getTo()),
    date: formatDate_(message.getDate()),
    plain_body: truncateText(message.getPlainBody(), MAX_BODY_CHARS),
    html_body: truncateText(message.getBody(), MAX_BODY_CHARS),
    attachments: extractAttachmentMetadata_(attachments),
    headers: {
      'Authentication-Results': getHeaderSafely_(message, 'Authentication-Results'),
      'Return-Path': getHeaderSafely_(message, 'Return-Path'),
      'Received-SPF': getHeaderSafely_(message, 'Received-SPF'),
      'From': getHeaderSafely_(message, 'From'),
      'Reply-To': getHeaderSafely_(message, 'Reply-To'),
    },
  };
}

function splitRecipients_(value) {
  if (!value) {
    return [];
  }
  return String(value)
    .split(',')
    .map(function(recipient) {
      return recipient.trim();
    })
    .filter(function(recipient) {
      return recipient.length > 0;
    });
}

function extractAttachmentMetadata_(attachments) {
  var limitedAttachments = (attachments || []).slice(0, MAX_ATTACHMENTS);
  return limitedAttachments.map(function(attachment) {
    return {
      filename: safeText(attachment.getName()),
      mime_type: safeText(attachment.getContentType()),
    };
  });
}

function getHeaderSafely_(message, headerName) {
  try {
    return safeText(message.getHeader(headerName));
  } catch (error) {
    return '';
  }
}

function formatDate_(dateValue) {
  if (!dateValue) {
    return null;
  }
  try {
    return dateValue.toISOString();
  } catch (error) {
    return String(dateValue);
  }
}

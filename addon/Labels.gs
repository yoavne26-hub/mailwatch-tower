/**
 * Placeholder for future optional Gmail risk labels.
 */

function buildLabelFeatureUnavailableCard() {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      'Persistent Gmail risk labels are planned as an optional feature. They are not enabled in the MVP because applying labels requires broader Gmail modification permissions.'
    ));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Risk labels unavailable')
      .setSubtitle(APP_NAME))
    .addSection(section)
    .build();
}

function maybeApplyRiskLabelPlaceholder() {
  return buildLabelFeatureUnavailableCard();
}

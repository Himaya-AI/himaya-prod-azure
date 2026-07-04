/**
 * Helios Phish Reporter — Google Workspace Add-on
 * 
 * Single published add-on that works across ALL Helios customers.
 * No configuration needed — tenant is resolved automatically from
 * the reporter's email domain via the Helios keyless API.
 * 
 * Helios by Himaya Technologies — helios.himaya.ai
 */

var HELIOS_API = 'https://helios.himaya.ai';

/**
 * Triggered when a Gmail message is opened.
 * Renders the "Report Phishing" card in the sidebar.
 */
function onGmailMessageOpen(e) {
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  var message = GmailApp.getMessageById(messageId);
  var subject = message ? message.getSubject() : '(unknown)';
  var from = message ? message.getFrom() : '(unknown)';

  // Truncate subject for display
  var displaySubject = subject.length > 50 ? subject.substring(0, 50) + '...' : subject;

  var card = CardService.newCardBuilder()
    .setName('Helios Phish Reporter')
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Helios Security')
        .setSubtitle('AI-Powered Email Protection')
        .setImageUrl('https://helios.himaya.ai/himaya-logo.png')
        .setImageStyle(CardService.ImageStyle.CIRCLE)
    )
    .addSection(
      CardService.newCardSection()
        .setHeader('📧 Current email')
        .addWidget(
          CardService.newKeyValue()
            .setTopLabel('From')
            .setContent(from)
        )
        .addWidget(
          CardService.newKeyValue()
            .setTopLabel('Subject')
            .setContent(displaySubject)
        )
    )
    .addSection(
      CardService.newCardSection()
        .setHeader('Report suspicious email')
        .addWidget(
          CardService.newTextParagraph()
            .setText('If this email looks suspicious or is a phishing attempt, report it to your security team. Helios AI will investigate immediately.')
        )
        .addWidget(
          CardService.newTextButton()
            .setText('🚨 Report as Phishing')
            .setBackgroundColor('#ef4444')
            .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
            .setOnClickAction(
              CardService.newAction()
                .setFunctionName('reportPhishing')
                .setParameters({ 'messageId': messageId, 'accessToken': accessToken })
            )
        )
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('<font color="#64748b"><small>Powered by Helios · helios.himaya.ai</small></font>')
        )
    )
    .build();

  return [card];
}

/**
 * Called when user clicks "Report as Phishing".
 * Submits to the keyless Helios API endpoint — no API key needed,
 * tenant is resolved by the reporter's email domain automatically.
 */
function reportPhishing(e) {
  var messageId = e.parameters.messageId;
  var accessToken = e.parameters.accessToken;

  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);

  if (!message) {
    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification()
          .setText('❌ Could not access the email. Please try again.')
      )
      .build();
  }

  var reporterEmail = Session.getActiveUser().getEmail();
  var subject = message.getSubject();
  var from = message.getFrom();
  var senderDomain = '';
  try {
    senderDomain = from.match(/@([^>]+)/)[1].trim();
  } catch(err) {
    senderDomain = from;
  }
  var bodyPreview = message.getPlainBody().substring(0, 500);
  var receivedDate = '';
  try { receivedDate = message.getDate().toISOString(); } catch(err) {}

  var payload = {
    reporter_email: reporterEmail,
    subject: subject,
    sender: from,
    sender_domain: senderDomain,
    body_preview: bodyPreview,
    message_id: messageId,
    received_at: receivedDate,
    provider: 'gmail'
  };

  var options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    var response = UrlFetchApp.fetch(HELIOS_API + '/api/phish-report/submit-keyless', options);
    var code = response.getResponseCode();

    if (code === 200) {
      // Apply a local label so the user knows it's under review
      try {
        var label = GmailApp.getUserLabelByName('Helios-Review');
        if (!label) { label = GmailApp.createLabel('Helios-Review'); }
        var thread = message.getThread();
        thread.addLabel(label);
      } catch(labelErr) { /* non-fatal */ }

      return CardService.newActionResponseBuilder()
        .setNotification(
          CardService.newNotification()
            .setText('✅ Reported! Helios AI is investigating this email.')
        )
        .setStateChanged(true)
        .build();

    } else {
      Logger.log('Helios report failed: ' + code + ' ' + response.getContentText());
      return CardService.newActionResponseBuilder()
        .setNotification(
          CardService.newNotification()
            .setText('⚠️ Report failed (code ' + code + '). Contact your admin if this persists.')
        )
        .build();
    }

  } catch(err) {
    Logger.log('Helios report error: ' + err.toString());
    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification()
          .setText('❌ Network error. Please check your connection and try again.')
      )
      .build();
  }
}

package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Date;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {
    /** CUSTOM CONSTANTS */
    private final int LEFT_TITLE_PAGE = 6;
    private final int LEFT_AMOUNT_PAGE = 7;
    private final int EXPIRE_TITLE_PAGE = 8;
    private final int EXPIRE_DATE_PAGE = 9;
    private final String LEFT_TITLE = "left";
    private final String EXPIRE_TITLE = "expr";
    private final String EXPIRE_NOT_STARTED = "TBA-";
    private final int EXPIRE_TIME_MIN = 1;
    private final int ISSUE_AMOUNT = 5;

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    /** TODO: Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationKey = defaultAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private int remainingUses = 0;
    private final int expiryTime = 0;

    private static String infoToShow = "-"; // Use this to show messages

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() { return isValid; }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() { return remainingUses; }

    /** After validation, get the expiry time */
    public int getExpiryTime() { return expiryTime; }

    /** After validation/issuing, get information */
    public static String getInfoToShow() { return infoToShow; }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        Utilities.log("issue()", true);

        String currentFailMsg = "";
        boolean wasExpired;
        try { // NOTE: every method starting with 'try' can raise Exception
            // Authenticate
            currentFailMsg = "Authentication failed";
            tryAuthenticate();

            // Formatting:
            // Add "left" title if needed
            currentFailMsg = "Left title reading failed";
            String leftTitle = tryReadPage(LEFT_TITLE_PAGE);
            if (!leftTitle.equals(LEFT_TITLE)) {
                currentFailMsg = "Left title writing failed";
                tryWritePage(LEFT_TITLE_PAGE, LEFT_TITLE);
            }
            // Add "expr" title if needed
            currentFailMsg = "Expire title reading failed";
            String exprTitle = tryReadPage(EXPIRE_TITLE_PAGE);
            if (!exprTitle.equals(EXPIRE_TITLE)) {
                currentFailMsg = "Expire title writing failed";
                tryWritePage(EXPIRE_TITLE_PAGE, EXPIRE_TITLE);
            }

            // Read how many uses left, initialize with 0 if not set
            currentFailMsg = "Reading left amount failed";
            String leftAmountString = tryReadPage(LEFT_AMOUNT_PAGE);
            int leftAmount;
            try {
                currentFailMsg = "Converting left amount failed";
                leftAmount = tryStringToInt(leftAmountString);
            } catch(java.lang.NumberFormatException e) {
                currentFailMsg = "Initial left amount writing failed";
                tryWritePage(LEFT_AMOUNT_PAGE, "0000");
                leftAmount = 0;
            }

            // Calculate new amount based on if expired or not
            currentFailMsg = "Expire read failed";
            int newAmount;
            if (hasExpired(tryReadBytes(EXPIRE_DATE_PAGE))) {
                wasExpired = true;
                newAmount = ISSUE_AMOUNT;
            } else {
                wasExpired = false;
                newAmount = leftAmount + ISSUE_AMOUNT;
            }

            // Reset expire
            currentFailMsg = "Expire date write failed";
            tryWritePage(EXPIRE_DATE_PAGE, EXPIRE_NOT_STARTED);

            // Issue new
            currentFailMsg = "Left amount writing failed";
            tryWritePage(LEFT_AMOUNT_PAGE, intToPageString(newAmount));

            // Update state
            remainingUses = newAmount;
            isValid = true;
        } catch (Exception e) {
            logErrorAndInfo(currentFailMsg);
            isValid = false;
            return false;
        }

        if (!wasExpired) {
            logErrorAndInfo("Issue success! Uses left: " + remainingUses);
        } else {
            logErrorAndInfo(
                    "Issue success! Uses left: " + remainingUses +
                    " (old tickets had expired or did not exist)"
            );
        }
        return true;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        Utilities.log("use()", true);

        String currentFailMsg = "";
        try { // NOTE: every method starting with 'try' can raise Exception
            // Authenticate
            currentFailMsg = "Authentication failed";
            tryAuthenticate();

            // Read how many uses left
            currentFailMsg = "Reading left amount failed";
            String leftAmountString = tryReadPage(LEFT_AMOUNT_PAGE);
            int leftAmount;
            try {
                currentFailMsg = "Converting left amount failed";
                leftAmount = tryStringToInt(leftAmountString);
            } catch(java.lang.NumberFormatException e) {
                throw new Exception("No left amount initialized, issue() first!");
            }

            // Validate
            if (leftAmount < 1) {
                currentFailMsg = "No uses left";
                throw new Exception("not valid");
            }

            // Check if expired
            // Calculate new amount based on if expired or not
            currentFailMsg = "Expire read failed";
            byte[] exprBytes = tryReadBytes(EXPIRE_DATE_PAGE);
            if (hasExpired(exprBytes)) {
                currentFailMsg = "Tickets expired";
                throw new Exception("expired");
            }

            // Start expire countdown if not started yet
            if (!hasStarted(exprBytes)) {
                currentFailMsg = "Expire write failed";
                byte[] expireBytes = ByteBuffer.allocate(4).putInt(
                        currentDateMinInt() + EXPIRE_TIME_MIN
                ).array();
                tryWriteBytes(EXPIRE_DATE_PAGE, expireBytes);
            }

            // Use
            currentFailMsg = "Left amount writing failed";
            int newAmount = leftAmount - 1;
            tryWritePage(LEFT_AMOUNT_PAGE, intToPageString(newAmount));

            // Update state
            remainingUses = newAmount;
            isValid = true;
        } catch (Exception e) {
            logErrorAndInfo(currentFailMsg);
            isValid = false;
            return false;
        }
        logErrorAndInfo("Success! Uses left: " + remainingUses);
        return true;
    }

    /**
     * CUSTOM IMPLEMENTATION BELOW
     */

    private void tryAuthenticate() throws Exception {
        if(!utils.authenticate(authenticationKey)){
            throw new Exception("Auth failed");
        }
    }

    private byte[] tryReadBytes(int page) throws Exception {
        byte[] bytes = new byte[4];
        if(!utils.readPages(page, 1, bytes, 0)) {
            throw new Exception("Bytes read failed");
        }
        return bytes;
    }

    private void tryWriteBytes(int page, byte[] messageBytes) throws Exception {
        if(!writePage(page, messageBytes)) {
            throw new Exception("Page write failed");
        }
    }

    private String tryReadPage(int page) throws Exception {
        return new String(tryReadBytes(page));
    }

    private void tryWritePage(int page, String message) throws Exception {
        assert message.length() == 4: "Page length must be 4";
        tryWriteBytes(page, message.getBytes());
    }

    private void logErrorAndInfo(String message) {
        infoToShow = message;
        Utilities.log(message, true);
    }

    private String intToPageString(int Int) {
        return String.format("%04d", Int);
    }

    private int tryStringToInt(String page) {
        return Integer.parseInt(page);
    }

    private boolean hasStarted(byte[] dateBytes) {
        return !(new String(dateBytes).equals(EXPIRE_NOT_STARTED));
    }

    private int currentDateMinInt() {
        return (int) ((new Date()).getTime() / 1000 / 60);
    }

    private boolean hasExpired(byte[] dateBytes) {
        if (!hasStarted(dateBytes)) {
            return false;
        }
        int dateMinInt = new BigInteger(dateBytes).intValue();
        return dateMinInt < currentDateMinInt();
    }

    /**
     * Write one page
     *
     * @param page      page number
     * @param message   message to write
     * @return boolean value of success
     */
    private boolean writePage(int page, byte[] message) {
        return utils.writePages(message, 0, page, 1);
    }
}
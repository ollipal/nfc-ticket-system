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
    private final int LAST_TITLE_PAGE = 6;
    private final int LAST_COUNTER_PAGE = 7;
    private final int EXPIRE_TITLE_PAGE = 8;
    private final int EXPIRE_DATE_PAGE = 9;
    private final int COUNT_PAGE = 41;
    private final byte[] COUNT_ADD_ONE =  {(byte)1, (byte)0x00, (byte)0x00, (byte)0x00}; // TODO test with blank card to make sure is a valid COMPATIBILITY WRITE
    private final String LEFT_TITLE = "last";
    private final String EXPIRE_TITLE = "expr";
    private final String EXPIRE_NOT_STARTED = "TBA-";
    private final int EXPIRE_TIME_MIN = 1;
    private final int ISSUE_AMOUNT = 5;

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes(); // "saatananvittu".getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    /** TODO: Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationKey =  defaultAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;

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

        String currentFailMsg = ""; // This message will be shown/logged if the following method(s) fail
        boolean wasExpired;
        try { // NOTE: every method starting with 'try' can raise Exception
            // Authenticate
            currentFailMsg = "Authentication failed";
            tryAuthenticate();

            // These set the read/write protection to all general + lock pages!
            writePage(42, new byte[] {(byte)3, (byte)0x00, (byte)0x00, (byte)0x00}); // AUTH0 to 03h,0,0,0
            writePage(43, new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}); // AUTH1 to 0,0,0,0

            // Formatting:
            // Add "last" title if needed
            currentFailMsg = "Last title reading failed";
            String leftTitle = tryReadPage(LAST_TITLE_PAGE);
            if (!leftTitle.equals(LEFT_TITLE)) {
                currentFailMsg = "Last title writing failed";
                tryWritePage(LAST_TITLE_PAGE, LEFT_TITLE);
            }
            // Add "expr" title if needed
            currentFailMsg = "Expire title reading failed";
            String exprTitle = tryReadPage(EXPIRE_TITLE_PAGE);
            if (!exprTitle.equals(EXPIRE_TITLE)) {
                currentFailMsg = "Expire title writing failed";
                tryWritePage(EXPIRE_TITLE_PAGE, EXPIRE_TITLE);
            }

            // Calculate new amount based on if expired or not
            currentFailMsg = "Expire read failed";
            wasExpired = hasExpired(tryReadBytes(EXPIRE_DATE_PAGE));

            // Get usage count
            currentFailMsg = "Counter reading failed";
            int count = tryGetCount();

            // Calculate how many tickets left, save the valid unused ones
            currentFailMsg = "Reading last valid ticket failed";
            String lastTicketString = tryReadPage(LAST_COUNTER_PAGE);
            int lastTicket;
            int newAmount;
            try {
                lastTicket = Integer.parseInt(lastTicketString);
                if (!wasExpired && lastTicket > count) {
                    newAmount = ISSUE_AMOUNT + lastTicket - count;
                } else {
                    newAmount = ISSUE_AMOUNT;
                }
            } catch(java.lang.NumberFormatException e) {
                newAmount = ISSUE_AMOUNT;
            }

            // Reset expire
            currentFailMsg = "Expire date write failed";
            tryWritePage(EXPIRE_DATE_PAGE, EXPIRE_NOT_STARTED);

            // Issue new
            currentFailMsg = "Ticket amount writing failed";
            tryWritePage(LAST_COUNTER_PAGE, intToPageString(count + newAmount));

            // Update state
            remainingUses = newAmount;
            isValid = true;
            expiryTime = 0;
        } catch (Exception e) {
            logErrorAndInfo(currentFailMsg);
            isValid = false;
            return false;
        }

        if (!wasExpired) {
            logErrorAndInfo("Issue success! " + remainingUses + " tickets left");
        } else {
            logErrorAndInfo(
                    "Issue success!  " + remainingUses + " tickets left" +
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
        utils.log("use()", true);

        /*
            Replay protection TODO make online
            key: UUID value: { issue, last counter value }
         */

        //Utilities.log(new String(macAlgorithm.generateMac("test".getBytes())), true);

        String currentFailMsg = ""; // This message will be shown/logged if the following method(s) fail
        try { // NOTE: every method starting with 'try' can raise Exception
            // Authenticate
            currentFailMsg = "Authentication failed";
            tryAuthenticate();

            // ENABLE DUMP AGAIN BY UNCOMMENTING, do not remove
            //writePage(42, new byte[] {(byte)48, (byte)0x00, (byte)0x00, (byte)0x00}); // AUTH0 to 30h,0,0,0

            // Get usage count
            int count = tryGetCount();

            // Read how many uses left
            currentFailMsg = "Reading ticket amount failed";
            String lastTicketString = tryReadPage(LAST_COUNTER_PAGE);
            int lastTicket;
            try {
                lastTicket = Integer.parseInt(lastTicketString);
            } catch(java.lang.NumberFormatException e) {
                currentFailMsg = "Converting ticket amount failed";
                throw new Exception("Converting ticket amount failed");
            }

            // Validate
            if (lastTicket - count < 1) {
                currentFailMsg = "No tickets left";
                throw new Exception("No tickets left");
            }

            // Check if expired
            currentFailMsg = "Expire read failed";
            byte[] exprBytes = tryReadBytes(EXPIRE_DATE_PAGE);
            if (hasExpired(exprBytes)) {
                expiryTime = bytesToInt(exprBytes);
                currentFailMsg = "Tickets expired";
                throw new Exception("Tickets expired");
            }

            // Use
            int newAmount = lastTicket - count - 1;
            currentFailMsg = "Ticket counter increment failed";
            tryIncrementCount();

            // Start expire countdown if not started yet, update expiryTime
            if (!hasStarted(exprBytes)) {
                currentFailMsg = "Expire write failed";
                expiryTime = currentDateMinInt() + EXPIRE_TIME_MIN;
                tryWriteBytes(EXPIRE_DATE_PAGE, intToBytes(expiryTime));
            } else {
                expiryTime = bytesToInt(exprBytes);
            }

            // Update state
            remainingUses = newAmount;
            isValid = true;
        } catch (Exception e) {
            logErrorAndInfo(currentFailMsg);
            isValid = false;
            return false;
        }
        logErrorAndInfo("Success! " + remainingUses + " tickets left");
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

    private int tryGetCount() throws Exception {
        byte[] countBytes = tryReadBytes(COUNT_PAGE);
        byte[] actualCountBytes = {countBytes[1], countBytes[0]};
        return bytesToInt(actualCountBytes);
    }

    private void tryIncrementCount() throws Exception {
        tryWriteBytes(COUNT_PAGE, COUNT_ADD_ONE);
    }

    private int bytesToInt(byte[] bytes) {
        return new BigInteger(bytes).intValue();
    }

    private byte[] intToBytes(int intVal) {
        return ByteBuffer.allocate(4).putInt(intVal).array();
    }

    private boolean writePage(int page, byte[] message) {
        return utils.writePages(message, 0, page, 1);
    }

    private String intToPageString(int Int) {
        return String.format("%04d", Int);
    }

    private int currentDateMinInt() {
        return (int) ((new Date()).getTime() / 1000 / 60);
    }

    private boolean hasStarted(byte[] dateBytes) {
        return !(new String(dateBytes).equals(EXPIRE_NOT_STARTED));
    }

    private boolean hasExpired(byte[] dateBytes) {
        if (!hasStarted(dateBytes)) {
            return false;
        }
        return bytesToInt(dateBytes) < currentDateMinInt();
    }

    private void logErrorAndInfo(String message) {
        infoToShow = message;
        utils.log(message, true);
    }
}
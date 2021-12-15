package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {
    /** CUSTOM CONSTANTS */
    private final int VERSION_TITLE_PAGE = 4;
    private final int VERSION_VALUE_PAGE = 5;
    private final int FIRST_TITLE_PAGE = 6;
    private final int FIRST_COUNTER_PAGE = 7;
    private final int LAST_TITLE_PAGE = 8;
    private final int LAST_COUNTER_PAGE = 9;
    private final int EXPIRE_TITLE_PAGE = 10;
    private final int EXPIRE_DATE_PAGE = 11;
    private final int HMAC_TITLE_PAGE = 12;
    private final int HMAC_VALUE_PAGE = 13;
    private final int HMAC2_TITLE_PAGE = 14;
    private final int HMAC2_VALUE_PAGE = 15;
    private final int COUNT_PAGE = 41;
    private final byte[] COUNT_ADD_ONE =  {(byte)1, (byte)0x00, (byte)0x00, (byte)0x00}; // TODO test with blank card to make sure is a valid COMPATIBILITY WRITE
    private final String VERSION_TITLE = "VERS";
    private final String VERSION_VALUE = "0001";
    private final String FIRST_TITLE = "FRST";
    private final String LEFT_TITLE = "LAST";
    private final String EXPIRE_TITLE = "EXPR";
    private final String EXPIRE_NOT_STARTED = "tba-";
    private final String HMAC_TITLE = "HMAC";
    private final String HMAC2_TITLE = "HMA2";
    private final int EXPIRE_TIME_MIN = 1;
    private final int ISSUE_AMOUNT = 5;

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    /** TODO: Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationKey =  defaultAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    // these are the new random keys, that are used in calcKey as input for the hash
    private static final byte[] authenticationKey2 =  "4YUS2291X58HGZ8G".getBytes(); // 16-byte key
    private static final byte[] hmacKey2 = "JH0SCT74YJYSXNUE".getBytes(); // 16-byte key

    public static byte[] data = new byte[192];

    private static HashMap<Integer, Integer> replayProtectionMap = new HashMap<Integer, Integer>();

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
            // Get UID
            currentFailMsg = "UID getting failed";
            int uid = tryGetUid();

            // Check if still has the default authentication key
            // If yes, update to one derived from the uid and a new master secret
            if(utils.authenticate(authenticationKey)){
                logErrorAndInfo("Default key still used...");
                utils.writePages(calcKey(uid, authenticationKey2), 0, 44, 4); // writes a new authentication key
                logErrorAndInfo("The key has been updated");
            }else{
                logErrorAndInfo("The key has been updated earlier already");
            }

            // Authenticate
            currentFailMsg = "Authentication failed";
            tryAuthenticate(uid);

            // These set the read/write protection to all general + lock pages!
            writePage(42, new byte[] {(byte)3, (byte)0x00, (byte)0x00, (byte)0x00}); // AUTH0 to 03h,0,0,0
            writePage(43, new byte[] {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00}); // AUTH1 to 0,0,0,0

            // Formatting:
            // Add "vers" title if needed
            currentFailMsg = "Version title reading failed";
            String versionTitle = tryReadPage(VERSION_TITLE_PAGE);
            if (!versionTitle.equals(VERSION_TITLE)) {
                currentFailMsg = "Version title writing failed";
                tryWritePage(VERSION_TITLE_PAGE, VERSION_TITLE);
            }
            // Add version value if needed
            currentFailMsg = "Version value reading failed";
            String versionValue = tryReadPage(VERSION_VALUE_PAGE);
            if (!versionValue.equals(VERSION_VALUE)) {
                currentFailMsg = "Version value writing failed";
                tryWritePage(VERSION_VALUE_PAGE, VERSION_VALUE);
            }
            // Add "frst" title if needed
            currentFailMsg = "First title reading failed";
            String firstTitle = tryReadPage(FIRST_TITLE_PAGE);
            if (!firstTitle.equals(FIRST_TITLE)) {
                currentFailMsg = "Last title writing failed";
                tryWritePage(FIRST_TITLE_PAGE, FIRST_TITLE);
            }
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
            // Add "hmac" title if needed
            currentFailMsg = "Hmac title reading failed";
            String hmacTitle = tryReadPage(HMAC_TITLE_PAGE);
            if (!hmacTitle.equals(HMAC_TITLE)) {
                currentFailMsg = "Hmac title writing failed";
                tryWritePage(HMAC_TITLE_PAGE, HMAC_TITLE);
            }
            // Add "hma2" title if needed
            currentFailMsg = "Hmac2 title reading failed";
            String hmac2Title = tryReadPage(HMAC2_TITLE_PAGE);
            if (!hmac2Title.equals(HMAC2_TITLE)) {
                currentFailMsg = "Hmac2 title writing failed";
                tryWritePage(HMAC2_TITLE_PAGE, HMAC2_TITLE);
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
            String lastTicketStringNew = intToPageString(count + newAmount);
            currentFailMsg = "Ticket amount writing failed";
            tryWritePage(FIRST_COUNTER_PAGE, intToPageString(count));
            tryWritePage(LAST_COUNTER_PAGE, lastTicketStringNew);

            // Save HMAC
            byte[] hmac = calcHmac(lastTicketStringNew, uid);
            currentFailMsg = "HMAC writing failed";
            tryWriteBytes(HMAC_VALUE_PAGE, hmac);

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

        String currentFailMsg = ""; // This message will be shown/logged if the following method(s) fail
        try { // NOTE: every method starting with 'try' can raise Exception
            // Get UID
            currentFailMsg = "UID getting failed";
            int uid = tryGetUid();

            // Authenticate
            currentFailMsg = "Authentication failed";
            tryAuthenticate(uid);

            // ENABLE DUMP AGAIN BY UNCOMMENTING, do not remove
            writePage(42, new byte[] {(byte)48, (byte)0x00, (byte)0x00, (byte)0x00}); // AUTH0 to 30h,0,0,0

            // Get usage count
            currentFailMsg = "Getting count failed";
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

            // Verify HMAC
            byte[] hmacStored = tryReadBytes(HMAC_VALUE_PAGE);
            byte[] hmacCalc = calcHmac(lastTicketString, uid);
            if(!Arrays.equals(hmacStored, hmacCalc)) {
                currentFailMsg = "HMAC does not add up";
                throw new Exception("HMAC does not add up");
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

            // Start expire countdown if not started yet
            // If not, check that the counter value has not been altered
            // and then update expiryTime
            if (!hasStarted(exprBytes)) {
                // Verify counter value is still the original
                currentFailMsg = "First value reading failed";
                int first = tryGetFirst();
                if (first != count) {
                    currentFailMsg = "Counter values do not add up";
                    throw new Exception("Counter values do not add up");
                }
                // Get expiry time
                expiryTime = currentDateMinInt() + EXPIRE_TIME_MIN;
                // Write hmac2 based on the expiry
                byte[] hmac2 = calcHmac2(lastTicketString, uid, expiryTime);
                currentFailMsg = "HMAC2 writing failed";
                tryWriteBytes(HMAC2_VALUE_PAGE, hmac2);
                // Write expiry
                currentFailMsg = "Expire write failed";
                tryWriteBytes(EXPIRE_DATE_PAGE, intToBytes(expiryTime));
            } else {
                expiryTime = bytesToInt(exprBytes);
                // Verify HMAC2
                byte[] hmac2Stored = tryReadBytes(HMAC2_VALUE_PAGE);
                byte[] hmac2Calc = calcHmac2(lastTicketString, uid, expiryTime);
                if(!Arrays.equals(hmac2Stored, hmac2Calc)) {
                    currentFailMsg = "HMAC2 does not add up";
                    throw new Exception("HMAC2 does not add up");
                }
            }

            // Check if replay attack
            currentFailMsg = "Getting count failed";
            if (replayProtectionMap.get(uid) != null) {
                if (replayProtectionMap.get(uid) == count) {
                    currentFailMsg = "Replay attack detected";
                    throw new Exception("Replay attack detected");
                }
            } else {
                utils.log("Adding new UID to the replayProtectionMap", true);
                replayProtectionMap.put(uid, count);
            }

            // Use
            int newAmount = lastTicket - count - 1;
            currentFailMsg = "Ticket counter increment failed";
            tryIncrementCount();

            // Update state
            remainingUses = newAmount;
            isValid = true;
        } catch (Exception e) {
            logErrorAndInfo(currentFailMsg);
            isValid = false;
            return false;
        }
        logErrorAndInfo("Success! " + remainingUses + " tickets left, expires in " + String.format("%.2f", ((expiryTime - currentDateMinInt()) / 60.0)) + " hours");
        return true;
    }

    /**
     * CUSTOM IMPLEMENTATION BELOW
     */

    private void tryAuthenticate(int uid) throws Exception {
        if(!utils.authenticate(calcKey(uid, authenticationKey2))){
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

    private int tryGetUid() throws Exception {
        // read parts
        byte[] uid1 = tryReadBytes(0);
        byte[] uid2 = tryReadBytes(1);
        // concat parts
        byte[] uid = byteConcat(uid1, uid2);
        // to int and return
        return bytesToInt(uid);
    }

    private byte[] byteConcat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    private int tryGetCount() throws Exception {
        byte[] countBytes = tryReadBytes(COUNT_PAGE);
        byte[] actualCountBytes = {countBytes[1], countBytes[0]};
        return bytesToInt(actualCountBytes);
    }

    private int tryGetFirst() throws Exception {
        String firstTicketString = tryReadPage(FIRST_COUNTER_PAGE);
        try {
            return Integer.parseInt(firstTicketString);
        } catch(java.lang.NumberFormatException e) {
            throw new Exception("Getting first failed");
        }
    }

    private void tryIncrementCount() throws Exception {
        tryWriteBytes(COUNT_PAGE, COUNT_ADD_ONE);
    }

    private byte[] calcHmac(String lastCounter, int uid) {
        byte[] hmacLong = macAlgorithm.generateMac(byteConcat(calcKey(uid, hmacKey2), (lastCounter + VERSION_VALUE + uid).getBytes()));
        byte[] hmac4bytes = new byte[4];
        System.arraycopy(hmacLong, 0, hmac4bytes, 0, 4);
        return hmac4bytes;
    }

    private byte[] calcHmac2(String lastCounter, int uid, int expiryTime) {
        byte[] hmacLong = macAlgorithm.generateMac(byteConcat(calcKey(uid, hmacKey2), (lastCounter + VERSION_VALUE + uid + expiryTime).getBytes()));
        byte[] hmac4bytes = new byte[4];
        System.arraycopy(hmacLong, 0, hmac4bytes, 0, 4);
        return hmac4bytes;
    }

    // calculates 16bit key based on the input
    private byte[] calcKey(int uid, byte[] secret) {
        byte[] hmacLong = macAlgorithm.generateMac(byteConcat(secret, ("" + uid).getBytes()));
        byte[] hmac16bytes = new byte[16];
        System.arraycopy(hmacLong, 0, hmac16bytes, 0, 16);
        return hmac16bytes;
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
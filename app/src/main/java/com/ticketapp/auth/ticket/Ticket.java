package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {

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

    private final Boolean isValid = false;
    private final int remainingUses = 0;
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
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        Utilities.log("Normal Mode, Issue: issue()", true);
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // Example of writing:
        String message = "test";
        res = writePage(6, message); //utils.writePages(message, 0, 6, 1);

        // Set information to show for the user
        if (res) {
            infoToShow = "Wrote: " + message;
        } else {
            infoToShow = "Failed to write";
        }

        return true;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        Utilities.log("Normal Mode, Validate: use()", true);
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // Example of reading:
        byte[] message = new byte[4];
        res =  readPage(6, message);

        // Set information to show for the user
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }

    /**
     * CUSTOM IMPLEMENTATION BELOW
     */
    private byte[] intToPage(int Int) {
        return String.format("%04d", Int).getBytes();
    }

    private int pageToInt(byte[] page) {
        return Integer.parseInt(page.toString());
    }

    /**
     * Write one page
     *
     * @param page      page number
     * @param message   message to write
     * @return boolean value of success
     */
    private boolean writePage(int page, String message) {
        assert message.length() == 4: "Page length must be 4";
        return utils.writePages(message.getBytes(), 0, page, 1);
    }

    /**
     * Read one page
     *
     * @param page      page number
     * @param message   message to read
     * @return boolean value of success
     */
    private boolean readPage(int page, byte[] message) {
        return utils.readPages(page, 1, message, 0);
    }
}
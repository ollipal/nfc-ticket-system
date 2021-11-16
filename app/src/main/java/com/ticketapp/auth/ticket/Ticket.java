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
    /** CUSTOM CONSTANTS */
    private final int LEFT_PAGE_TITLE = 6;
    private final int LEFT_PAGE_AMOUNT = 7;
    private final int ISSUE_AMOUNT = 5;
    private final String LEFT_TITLE = "left";

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
        Utilities.log("Normal Mode, Issue: issue()", true);
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // Set validity to false initially
        isValid = false;

        // Add left title if needed
        byte[] titleBytes = new byte[4];
        res = utils.readPages(LEFT_PAGE_TITLE, 1, titleBytes, 0);
        if (!res) {
            Utilities.log("Left title reading failed", true);
            infoToShow = "Reading failed";
            return false;
        }
        if (!(new String(titleBytes)).equals(LEFT_TITLE)) {
            // Write left title
            res = writeString(LEFT_PAGE_TITLE, LEFT_TITLE);
            if (!res) {
                Utilities.log("Left title writing failed", true);
                infoToShow = "Writing failed";
                return false;
            }
        }

        // Set amount to 0 if no value
        byte[] amountBytes = new byte[4];
        //res = readPage(LEFT_PAGE_AMOUNT, amountBytes); // TODO why not work?
        res = utils.readPages(LEFT_PAGE_AMOUNT, 1, amountBytes, 0);
        if (!res) {
            Utilities.log("Reading amount failed", true);
            infoToShow = "Reading failed";
            return false;
        }
        try {
            pageToInt(amountBytes);
        } catch(java.lang.NumberFormatException e) {
            // Write initial amount of 0
            res = writeString(LEFT_PAGE_AMOUNT, "0000");
            if (!res) {
                Utilities.log("Initial amount writing failed", true);
                infoToShow = "Writing failed";
                return false;
            }
        }


        // Get current amount
        amountBytes = new byte[4];
        //res = readPage(LEFT_PAGE_AMOUNT, amountBytes); // TODO why not work?
        res = utils.readPages(LEFT_PAGE_AMOUNT, 1, amountBytes, 0);
        if (!res) {
            Utilities.log("Reading amount failed", true);
            infoToShow = "Reading failed";
            return false;
        }
        int currentAmount = pageToInt(amountBytes);

        // Issue new
        res = writePage(LEFT_PAGE_AMOUNT, intToPage(currentAmount + ISSUE_AMOUNT));
        if (!res) {
            Utilities.log("Left amount writing failed", true);
            infoToShow = "Writing failed";
            return false;
        }

        // Write status
        remainingUses = currentAmount + ISSUE_AMOUNT;
        isValid = true;

        // Show success
        infoToShow = "Issue success!";
        Utilities.log("Issue success!", true);
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

        // Set validity to false initially
        isValid = false;

        // Get current amount
        byte[] amountBytes = new byte[4];
        //res = readPage(LEFT_PAGE_AMOUNT, amountBytes); // TODO why not work?
        res = utils.readPages(LEFT_PAGE_AMOUNT, 1, amountBytes, 0);
        if (!res) {
            Utilities.log("Reading amount failed", true);
            infoToShow = "Reading failed";
            return false;
        }
        int currentAmount;
        try {
            currentAmount = pageToInt(amountBytes);
        } catch(java.lang.NumberFormatException e) {
            // Write initial amount of 0
            Utilities.log("Reading amount failed", true);
            infoToShow = "Reading failed";
            return false;
        }

        // Validate
        if (currentAmount < 1) {
            infoToShow = "No uses left";
            Utilities.log("No uses left", true);
            return false;
        }

        // Use
        res = writePage(LEFT_PAGE_AMOUNT, intToPage(currentAmount - 1));
        if (!res) {
            Utilities.log("Left amount writing failed", true);
            infoToShow = "Writing failed";
            return false;
        }

        // Write status
        remainingUses = currentAmount - 1;
        isValid = true;

        // Show success
        infoToShow = "Use success!";
        Utilities.log("Use success!", true);
        return true;
    }

    /**
     * CUSTOM IMPLEMENTATION BELOW
     */

    private byte[] intToPage(int Int) {
        return String.format("%04d", Int).getBytes();
    }

    private int pageToInt(byte[] page) {
        return Integer.parseInt(new String(page));
    }

    /**
     * Write 4 character string to page
     *
     * @param page      page number
     * @param message   message to write
     * @return boolean value of success
     */
    private boolean writeString(int page, String message) {
        assert message.length() == 4: "Page length must be 4";
        return writePage(page, message.getBytes());
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
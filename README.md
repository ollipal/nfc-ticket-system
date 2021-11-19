# NFC ticket system

## Notes:

Modified files:
- Logic added: `nfc-ticket-system/app/src/main/java/com/ticketapp/auth/ticket/Ticket.java`
- Call order changed a bit to fix existing logs: `nfc-ticket-system/app/src/main/java/com/ticketapp/auth/app/fragments/EmulatorFragment.java`

Known issues:
- Issuing new tickets resets the expiry date for all non-expired tickets, not an issue probably?

## Implemented

- Issue tickets with constant number of rides (5)  
- Validate the ticket (check expiry time and remaining rides, decrement remaining rides) 
- The tickets are valid for a certain time (normally one day, but you can use one minute for testing) from the time when they were issued  
- Start the validity period only when the ticket is used for the first time (they can be given as gifts) 
- If the tickets have expired or they have been fully used, reformat the card and issue a new ticket (savings on blank tickets and friendlier to the environment) 
- Issue additional rides (+5) to a card without erasing any still valid ticket

## TODO

- Everything related to security
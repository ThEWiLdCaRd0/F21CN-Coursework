# Define class for constatants
    # TCP
    # UDP
    # ANY

# Define Class for Firewall Rules
    # Define fields that represent a firewall rule
        # Priority
        # Direction
        # IP Address
        # Port
        # Protocol
        # Action

    # Define rule matching process
   
        # Check rule for a specific direction: 
            # If not both then must match the rule direction exactly
            # If packet direction NOT match, return False
        
        # Unpack the rule’s source IP range into start ip and end ip variables for comparison
            # Check packet IP falls within the rule IP range: If outside range, return False
        
        # Check destination port: If rule specifies a particular port is not None 
            # Then the packet’s port must match. Otherwise, return False

        # Check the protocol type: If the rule specifies a particular protocol (not 'ANY'), 
            # The packet’s protocol must match. Otherwise, return False

        # If all the above checks pass: The packet matches this rule; show success by returning True

# Define the Firewall class

    # Initialze the Firewall Rule List object

    # Add rules to the firewall list

        # Initialize a counter (idx) to zero. 
            # This counter represents the index position in the rules list where the new rule should be inserted
        
        # Loop through the existing rules in priority order
            # Continue as long as idx is less than the number of rules
            # Check the rule at position idx has a priority lower than the new rule's priority. (lower priority numbers come first)
            # Increment idx each time until a rule with an equal or higher priority is found or the end of the list is reached
        
        # Insert new rule at the position idx
            # Move all existing rules at and after this index one spot further down the list

        # Renumber all the rules so that priorities are consecutive integers starting from 1
            # Loop over each rule (by index) in the list
            # Set each rule’s priority to its position in the list plus one 
    
    # Remove rules from the firewall list

        # Loop through the rules list using enumerate that gives both index (i) and rule object (rule)
        
            # Check if current rule’s priority matches requested priority (priority variable)
            # If match this is the rule the user wants to remove
            
                # Delete / remove the rule at index i from rules
                    # All rules after i move one slot up

                # After deleting, loop through the (now shorter) rule list 
                    # Set each rule’s priority attribute to its new position, starting with 1 for the first rule
                        # Renumbers the rules to ensure priorities stay unique and sequential

                # Return True immediately after removing and renumbering
                # This signals to caller that a rule was found and removed

        # If loop finishes without finding a rule with the given priority, return False. Signals no rule was removed because specified priority was not found
            
    # Modify rules in the firewall list

        # Loop through every rule in rules, using enumerate to get both idx and rule object (rule)

            # Check if current rule's priority matches the one you want to modify

                # If user wants to modify the priority field to change rule order

                    # Confirm new priority value is an integer, at least 1, and not greater than the total number of rules 
                    # If NOT met, immediately return False (modification failed)
                        # Value must be in bounds

                    # Remove rule, re-insert at target
                        # Remove rule from current position in the list return rule object

                    # Insert the rule object back into the list at the new position

                    # After moving, renumber all rules so their priority attributes match their position in the list, starting at 1

                    # Modification complete (priority move succeeded); Return True

                # ELSE some other field is being modified (not priority):
                    # Use set attrib (rule, field, value) to set the chosen field on the rule object
                        # Return True to signal the modification was successful

        # Modification operation unsuccessful because no rule with the specified priority was found 

    # Display rules in the firewall list
    
        # Loop through each rule in the firewall’s list of rules
            # Extract starting IP address from the rule’s source IP range; Convert to string for display

            # Extract ending IP address from the rule’s source IP range; Convert to string for display

            # Create the display string for the IP range 
                # If the startip and endip are different, show as "start-end" 
                # If they are the same (single IP),show the IP address

            # Set port display value: If the rule's destination port is set (not None), display its value
                # If None (meaning "any port"), display "*"

            # Print a formatted line for the rule <line spacing>
                # action (either 'allow'/'deny')  <line spacing>
                # direction ('in'/'out'/'both')  <line spacing>
                # IP range  (x.x.x.x-x.x.x.x) <line spacing>
                # port display (port)  <line spacing>
                # protocol ('TCP', 'UDP', or 'ANY')

    # Test packets for rule verification
    
        # Convert the packet's IP address from a string to an IPv4Address object
        
        # Check if protocol string matches one of the defined protocol types in the Protocol enum (TCP, UDP, ANY)
            # If it matches, create a Protocol enum object e.g. Protocol.TCP
        # If not, default to Protocol.ANY; match any protocol.

        # Loop through all rules in firewall, sorted by priority in ascending order

            # Call the matches method on the rule, passing in the packet’s direction, IP, destination port, and protocol
            # If the rule matches the packet (i.e., all criteria are satisfied), returns the rule's action ('allow' or 'deny') immediately (first matching rule determines the outcome.)

        # If no rule matched the packet as the loop completes, return 'deny' (implement implicit deny)

# Define IP adress parser class

    # Check if the string addr contains a hyphen (-). 
    # Determines if input is an IP range (like '10.0.0.1-10.0.0.10') or a single IP

        # If hyphen is present, split the string into two parts: start (before the hyphen) and end (after the hyphen)

        # Convert both parts to IPv4Address objects and remove any extra spaces from each part (Returns a tuple with the start and end IP addresses)

    # If no hyphen convert the entire addr string to an IPv4Address object (single IP)

        # Return a tuple with the same IP address twice (Standardize output to always return a tuple)

# Define get rule fields class (Prompt for all rule fields, keep visible until completion, set defaults if blank, validate field inputs)

    # While Loop
    
            # Prompt user to enter a priority number; strip leading/trailing whitespace from the input string; store in variable

            # If variable is a positive integer  and > 0, convert to an int and store in variable. Otherwise (blank or invalid) default to 1

            # Check if the chosen priority is greater than the maximum allowed value (one more than the current number of rules) 
            # If true print message and restart input for this rule

            # Prompt user for rule direction, strip spaces and convert to lowercase.
            # If user provides nothing, default to "both".

            # Validate entered direction is one of the allowed values
            # If false print an error and restart input for this rule.

            # Prompt user for IP address or IP range, strip spaces, and store the result in variable

            # If IP field was left blank, print error and restart input for this rule

            # Call IP parse function; that returns a tuple representing start and end IPs

            # Prompt for the destination port, strip whitespace, and store as port variable

            # If port field is blank or entered "*", sets port value to None (i.e. "any port")
                # Blank
                # *

            # check input only numbers
            # Verify value is within the valid TCP/UDP port range (0–65535)

                # If valid port number (0–65535), convert and store it
                # Otherwise, print error and restart input for this rule

            # prompt for protocol, strip spaces, convert to uppercase; default to "ANY" if blank

            # convert proto string to the corresponding proto enum value; Default to Protocol.ANY if unmatched

            # prompt for action, strip and lowercases user input; defaults to "deny" if blank
 
            # check if action is valid; if not, print error and restart input

            # print values entered by the user for review and confirmation
                # print Review entries
                # print Priority
                # print direction
                # print IP Range
                # print destination Port
                # print protocol
                # print action
                # Prompt for Confirm creation? (Y/N); Strip leading/trailing whitespace from the response
                # Convert the response to lowercase
            # IF response is exactly 'y'. If user typed 'y' = proceed.

            # ELSE
                # If user does not type 'y', print message rule creation canceled
                # Return control to input loop; start rule entry process again

        # If any error catch the exception

            # Print error message, including details from the exception

# Firewall CLI menu driven interface

    # Start infinite loop so program keeps prompting the user for actions until explicitly exited

        # Display menu (a string variable named menu that lists options) and collect user input

        # Start a match-case block
        # choice is compared to possible options

            # case 1  Add Rule
                # Gather all needed rule fields using get rule fields; passing the current number of rules for validation
                # Create a new FirewallRule by unpacking collected fields
                # Add this new rule to the firewall
                # Print a confirmation message

            # case 2  Remove Rule
                # try
                    # Prompt for priority number to remove
                    # Try to remove the rule with that priority
                    # Print if a rule was removed or not found
                        # rule removed
                        # no rule found
                    # If error / input can't be converted to integer, print an error

            # case 3  Modify Rule, includes priority edit/move
                # try
                    # Prompt for rule priority to modify and field to change

                    # Field-specific set of input checks/logic using chained if/elif/else blocks...)

                    # Check whether the field the user wants to change is 'priority'. 
                    # Only executes the following lines if this condition is True.
                    # if field == priority 
                        # Prompt for new priority value for the rule
                        # prompt tells the user the allowed range (from 1 to the current number of rules) and that the default is 1
                        # remove any leading/trailing whitespace from input; store result as a string

                        # Input validation and default, if user provided input is made up of digits and when converted to integer is greater than 0
                            # Convert to integer and use it as the new priority value. Otherwise (e.g., blank input or a non-digit), use 1 as default value

                        # Check if resulting value is less than 1 or greater than the total number of rules in the firewall
                            # If true print error message
                            # continue statement restarts the surrounding loop, re-prompting for input

                    # check IF choice selected IP address field to modify
                        # If true execute the following statements
                        # Prompt the user: "New IP/Range: "; reads input and remove any leading/trailing whitespace
                            # store response in variable
                        # Check whether ipr is an empty string <blank>
                            # If true print info message
                            # continue restarts input loop

                        # Call the IP parse function; passing the ipr variable as its argument
                            # ipr is expected to be a string representing either a single IP (e.g., "192.168.1.1") or an IP range (e.g., "192.168.1.1-192.168.1.10")
                            # This function processes ipr and returns a tuple: If ipr is a single IP, the tuple is (ip, ip) where both are IPv4Address objects
                            # If ipr is a range, the tuple is (start_ip, end_ip), both as IPv4Address objects
                            # Assigns the result of the function call to the variable value
                            # value now holds the parsed IP or range, which can be stored in a firewall rule for further use

                    # Check IF choice to modify the destination port
                    # ELIF field == dport 
                        # prompt to input new port number; the prompt info use '*' or leave blank for "any port"
                        # remove any leading or trailing spaces from input and store in port variable

                        # If input is blank or exactly an asterisk ('*'):
                            # Set value to None — i.e. rule matches any destination port.
                            # Convert the string port string to integer
                            # Assign integer to the variable value
                            # Set the destination port of the firewall rule to the input port variable value

                    # Check if choice to modify the protocol field
                    # IF true execute the next lines
                    # ELIF field == protocol
                        # prompt for new protocol; offering allowed options and a default: If the user presses Enter (blank input), default to "ANY"
                        # remove any extra spaces from the input; convert input to uppercase to ensure case-insensitive matching
                            # "ANY" ensures that if blank input is provided, protocol string will be "ANY"

                    # Check choice to modify direction 
                        # IF true execute the next lines
                    # ELIF field == direction
                        # Prompt new direction, explain that both is the default
                        # remove extra whitespace from the input
                        # convert input to lowercase for consistent comparison
                        # If <blank> (just presses Enter); or both sets the value to both
                            # Check if entered direction is valid (in, out, or both)
                            # If false, print error message
                            # continue re-starts the loop

                    # Check if the user selected the 'action' field to update. 
                        # IF true execute the next lines
                    # ELIF field == action
                        # Prompt to input new action value; if <blank> deny is the default
                        # remove extra whitespace
                        # convert input to lowercase; standardize input
                        # If input <blank> or deny sets value to deny.

                        # check if input either allow or deny
                            # If false, print error message
                            # continue restarts the loop

                    # Next block runs if the field name entered does not match any expected field names 
                    # (priority, direction, src_ip_range, dport, protocol, action).
                        # Print error message 
                        # continue  restarts the input process

                    # call the modify rule method on the fw Firewall object
                    # pass in the desired rule's priority, field to change, and new value 
                    # if modify rule returns True, modification was successful

                    # If modify rule returned False, prints an error message indicating: rule not found, field did not exist, Or value provided was invalid

                # Catch any exception that occurs during the modification attempt
                    # Print error message with the details of the exception (e)

            # List Rules
            # case 4
                # Calls the list rules method defined in the Firewall class. This method prints out all rules in the firewall object 

            # Test Packet for rule verification
            # case 5
                # try:
                    # Prompt input packet direction (in or out)
                    # Remove leading/trailing spaces, & make input lowercase
                    # If input <blank>, default to both

                    # Prompt for packet's source IP address
                    # Remove any extra spaces

                    # Prompt for packet destination port; Strip whitespace
                    # input can be blank or enter * to mean any port

                    # If input for port is blank or *, sets dport to None (meaning "any port")
                    # Otherwise, convert input to an integer for the specific port

                    # Prompt for protocol (TCP or UDP); strip whitespace and convert input to uppercase to "ANY" if left blank
                    
                    # Call the firewall packet action method; passing the gathered parameters
                        # This method checks all rules and returns either allow or deny based on the match

                    # Print result of firewall check; display allowed or denied

                # Catch any error that occurred in the block (e.g., invalid IP, bad port).
                    # Print error message

            # Exit program
            # case 6  
                # sys.exit() is a function that terminates the program immediately.

            # case _: is the default or "catch-all" case.
            # case _: 
                # print Unknown choice
# Best practice to limit code execution to direct calls and not to run if imported as a module

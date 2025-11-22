import ipaddress  # Official IPv4 library: https://docs.python.org/3/library/ipaddress.html
import enum       # Enums for protocol: https://docs.python.org/3/library/enum.html
import sys        # Program exit: https://docs.python.org/3/library/sys.html
from typing import List  # Type hints: https://docs.python.org/3/library/typing.html


class Protocol(enum.Enum):
    """Layer 4 protocols (TCP, UDP, ANY). See: https://docs.python.org/3/library/enum.html#creating-an-enum"""
    TCP = 'TCP'
    UDP = 'UDP'
    ANY = 'ANY'

class FirewallRule:
    """
    Represents a firewall rule.
    - priority: integer
    - direction: in, out, both
    - src_ip_range: tuple(ipaddress.IPv4Address, ipaddress.IPv4Address)
    - dport: int or None
    - protocol: Protocol
    - action: allow/deny
    """
    # define the fields used for the firewall program
    def __init__(self, priority: int, direction: str, src_ip_range, dport, protocol: Protocol, action: str):
        self.priority = priority
        self.direction = direction
        self.src_ip_range = src_ip_range
        self.dport = dport
        self.protocol = protocol
        self.action = action

    # Define the matching process to evaluate if traffic matches a rule in the list
    def matches(self, direction, ip, dport, protocol):
        """Packet matching. See: https://docs.python.org/3/library/ipaddress.html
            Each line performs a specific check (direction, IP range, port, protocol). 
            If the packet fails any check, it immediately returns False. 
            If all checks pass, it returns True—this packet matches the rule.
        """
        # Check if the rule is for a specific direction: 
        # If the rule’s direction is not 'both', then the packet’s direction must match the rule’s direction exactly. 
        # If the packet’s direction doesn’t match, return False (no match).
        if self.direction != 'both' and direction != self.direction: 
            return False
        # Unpack the rule’s source IP range into start_ip and end_ip variables for comparison.
        start_ip, end_ip = self.src_ip_range
        # Checks if the packet's IP falls within the rule’s IP range: If it’s outside the range, return False.
        if not (start_ip <= ip <= end_ip): 
            return False
        # Check the destination port: If the rule specifies a particular port (self.dport is not None), 
        # Then the packet’s port must match. Otherwise, return False.
        if self.dport is not None and self.dport != dport: 
            return False
        # Check the protocol type: If the rule specifies a particular protocol (not 'ANY'), 
        # The packet’s protocol must match. Otherwise, return False.
        if self.protocol != Protocol.ANY and self.protocol != protocol: 
            return False
        # If all the above checks pass: The packet matches this rule; indicate success by returning True.
        return True 

class Firewall:
    """
    Maintains and manipulates ordered list of FirewallRule. See: https://docs.python.org/3/tutorial/datastructures.html
    """
    # Initialze the Firewall Rule List object
    def __init__(self):
        self.rules: List[FirewallRule] = [] 

    # Method to add rules to the firewall list
    def add_rule(self, rule: FirewallRule):
        """Insert rule in priority order; renumber all. See: https://docs.python.org/3/tutorial/datastructures.html#more-on-lists
            This code finds the correct index to insert a new rule so that the list stays ordered by priority, inserts it, and then 
            renumbers all priorities to eliminate gaps or duplicates.
        """
        # Initialize a counter (idx) to zero. 
        # This counter will represent the index position in the rules list where the new rule should be inserted.
        idx = 0 
        # Loops through the existing rules in priority order: 
        # Continues as long as idx is less than the number of rules (len(self.rules)). 
        # Also checks that the rule at position idx has a priority lower than the new rule's priority. 
        # Reason; Finds the correct spot to insert the new rule so that the list remains sorted by priority 
        # (lower priority numbers come first). 
        # Increments idx each time until a rule with an equal or higher priority is found or the end of the list is reached.
        while idx < len(self.rules) and self.rules[idx].priority < rule.priority: 
            idx += 1
        # Insert the new rule at the position idx. Moves all existing rules at and after this index one spot further down the list.
        self.rules.insert(idx, rule)
        # Renumber all the rules so that priorities are consecutive integers starting from 1. 
        # Loop over each rule (by index) in the list. 
        # Set each rule’s priority to its position in the list plus one (so first rule is priority 1, second is 2, etc). 
        # Reason; Keeps priority numbers unique and sequential after insertion. 
        for i in range(len(self.rules)): 
            self.rules[i].priority = i + 1
    
    # Method to remove rules from the firewall list
    def remove_rule(self, priority):
        """Remove rule by priority. See: https://docs.python.org/3/tutorial/datastructures.html#del
            This code searches for a rule by priority; if found, deletes it, then renumbers all remaining rules for sequence, 
            and signals success. If not found, it returns failure.
        """
        # Loop through the list self.rules using enumerate, which gives both the index (i) and the rule object (rule). 
        # This setup lets you know the position of each rule as you look for the matching one.
        for i, rule in enumerate(self.rules): 
            # Check if the current rule’s priority matches the requested priority (priority variable). 
            # If it does, this is the rule the user wants to remove.
            if rule.priority == priority: 
                # Delete / remove the rule at index i from self.rules. 
                # The list now has one fewer rule, and all rules after i move one slot up.
                del self.rules[i] 
                # After deleting, loop through the (now shorter) rule list. 
                # Set each rule’s priority attribute to its new position, starting with 1 for the first rule. 
                # This renumbers the rules to ensure priorities stay unique and sequential (no skips or duplicates).
                for j in range(len(self.rules)): 
                    self.rules[j].priority = j + 1
                # Returns True immediately after removing and renumbering. 
                # This signals to the caller that a rule was found and removed.
                return True 
        # If the loop finishes without finding a rule with the given priority, returns False. 
        # This signals that no rule was removed, because the specified priority was not found.
        return False 

    # Method to modify rules in the firewall list
    def modify_rule(self, priority, field, value):
        """
        Update rule field. If field is 'priority', move rule to new priority and renumber so priorities are unique and consecutive.
        See: https://docs.python.org/3/library/functions.html#setattr
        """
        # Loops through every rule in self.rules, using enumerate to get both the index (idx) and the rule object (rule).
        for idx, rule in enumerate(self.rules): 
            # Checks whether the current rule's priority matches the one you want to modify.
            if rule.priority == priority: 
                # If the user wants to modify the priority field (i.e., move the rule to a new position in the list):
                if field == 'priority': 
                    # Makes sure the new priority value is an integer, at least 1, and not greater than the total number of rules. 
                    # If these conditions aren't met, immediately return False (modification failed).
                    if not isinstance(value, int) or value < 1 or value > len(self.rules): 
                        # Value must be in bounds
                        return False  
                    # Remove rule, re-insert at target
                    # Remove the rule from its current position in the list (pop(idx) returns the actual rule object).
                    rule_to_move = self.rules.pop(idx) 
                    # Insert the rule object back into the list at the new position. Since list indices start at 0, it does value - 1.
                    self.rules.insert(value - 1, rule_to_move) 
                    # After moving, renumbers all rules so their .priority attributes match their position in the list, starting at 1.
                    for i in range(len(self.rules)): 
                        self.rules[i].priority = i + 1
                    # Modification complete (priority move succeeded). Returns True.
                    return True 
                # If some other field is being modified (not priority):
                else: 
                    # Use setattr(rule, field, value) to set the chosen field on the rule object.
                    setattr(rule, field, value) 
                    # Return True to signal the modification was successful.
                    return True 
        # Requested rule modification operation did not succeed because no rule with the specified priority was found.
        return False

    """
    This block loops through all firewall rules and prints each one in a neatly aligned table, showing priority, action, direction, IP range, port, and protocol. It ensures single IPs and any-port rules are displayed in a friendly, readable way.
    """
    # Method to display rules in the firewall list
    def list_rules(self):
        """Display all rules. See: https://docs.python.org/3/library/functions.html#print"""
        print("\nPriority  Action   Dir   IP Range                 Port  Proto")
        print("-------------------------------------------------------------")
        # This loops through each rule (r) in the firewall’s list of rules (self.rules).
        for r in self.rules: 
            # Extracts the starting IP address from the rule’s source IP range. Converts it to a string for display.
            startip = str(r.src_ip_range[0]) 
            # Extracts the ending IP address from the rule’s source IP range. Converts it to a string for display.
            endip = str(r.src_ip_range[1]) 
            # Creates the display string for the IP range: If the startip and endip are different, show as "start-end" 
            # (e.g., "192.168.1.1-192.168.1.10"). 
            # If they are the same (just a single IP), just show the IP (e.g., "192.168.1.1").
            iprange = f"{startip}-{endip}" if startip != endip else startip 
            # Sets the port display value: If the rule's destination port (r.dport) is set (not None), displays its value. 
            # If None (meaning "any port"), it displays "*".
            port = r.dport if r.dport is not None else "*" 
            # Prints a formatted line for the rule, including: The rule's priority (r.priority), left-aligned in 8 spaces. 
            # The action (r.action, either 'allow'/'deny'), left-aligned 7 spaces. 
            # The direction (r.direction, 'in'/'out'/'both'), left-aligned 5 spaces.
            # The IP range display (iprange), left-aligned 22 spaces. 
            # The port display (port), left-aligned 5 spaces. 
            # The protocol (r.protocol.value; this gives 'TCP', 'UDP', or 'ANY').
            print(f"{r.priority:<8} {r.action:<7} {r.direction:<5} {iprange:<22} {port:<5} {r.protocol.value}") 

    """
    def packet_action(self, direction, ip_str, dport, proto_str):
    Test packet against rules. See: [https://docs.python.org/3/library/ipaddress.html](https://docs.python.org/3/library/ipaddress.html), https://docs.python.org/3/library/enum.html
    Defines a method packet_action, which belongs to the Firewall class.
    Parameters:
        direction: The direction of the packet (e.g., 'in', 'out').
        ip_str: The source IP address as a string (e.g., '192.168.1.1').
        dport: The destination port number (integer).
        proto_str: The protocol as a string (e.g., 'TCP', 'UDP').

        This method takes a packet description (direction, IP, port, protocol), checks each firewall rule in order of priority. 
        The first rule that matches returns its action ('allow'/'deny'). If no rule matches, the packet is denied by default. 
        All conversions (IP and protocol) use safe enum/standard library validation for reliability and clarity.
    """

    def packet_action(self, direction, ip_str, dport, proto_str):
        """Test packet against rules. See: https://docs.python.org/3/library/ipaddress.html, https://docs.python.org/3/library/enum.html"""
        # Convert the packet's IP address from a string (ip_str) to an IPv4Address object using the standard Python library (ipaddress.IPv4Address).
        # This enables safe, validated IP comparison and manipulation.
        ip = ipaddress.IPv4Address(ip_str) 
        # Check if the protocol string (proto_str) matches one of the defined protocol types in the Protocol enum (TCP, UDP, ANY). 
        # If it matches, it creates a Protocol enum object (e.g., Protocol.TCP). 
        # If not, it defaults to Protocol.ANY, meaning it will match any protocol.
        proto = Protocol(proto_str) if proto_str in Protocol.__members__ else Protocol.ANY 
        # Loops through all rules in the firewall, sorted by the priority attribute in ascending order (lower numbers indicate higher priority). 
        # Ensures that rules are checked in proper order, since priority determines which rule takes precedence.
        for r in sorted(self.rules, key=lambda x: x.priority): 
            # Call the matches method on the rule, passing in the packet’s direction, IP, destination port, and protocol. 
            # If the rule matches the packet (i.e., all criteria are satisfied), returns the rule's action ('allow' or 'deny') immediately. 
            # This means the first matching rule determines the outcome.
            if r.matches(direction, ip, dport, proto): 
                return r.action
        # If no rule matched the packet as the loop completes, this line returns 'deny'. 
        # This means the firewall implements a default-deny policy (i.e., "implicit deny" if none of the rules match the packet).
        return 'deny' 

def parse_ip_range(addr):
    """Parse single IP or range: https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address
        This block checks for a hyphen to distinguish an IP range from a single IP, parses accordingly, and returns either a (start, end) 
        tuple for a range or (ip, ip) for a single IP. Both results are suitable for further comparison and validation.
    """
    # Check if the string addr contains a hyphen (-). 
    # This determines whether the input is an IP range (like '10.0.0.1-10.0.0.10') or just a single IP.
    if '-' in addr: 
        # If a hyphen is present, splits the string into two parts: start (before the hyphen) and end (after the hyphen).
        start, end = addr.split('-') 
        # Convert both parts to IPv4Address objects using the ipaddress module. strip() removes any extra spaces from each part. 
        # Returns a tuple with the start and end IP addresses, representing an IP address range.
        return (ipaddress.IPv4Address(start.strip()), ipaddress.IPv4Address(end.strip())) 
    # If no hyphen is found, converts the entire addr string to an IPv4Address object (again stripping spaces). 
    # This means the input is just a single IP.
    ip = ipaddress.IPv4Address(addr.strip()) 
    # Returns a tuple with the same IP address twice. 
    # This standardizes the output so both cases (single IP and range) return a tuple, allowing the rest of the code to always unpack as start_ip, end_ip.
    return (ip, ip) 

def get_rule_fields(num_rules):
    """Prompt for all rule fields, keeps visible until completion, set defaults if blank.
        This code gets and validates each field for a new firewall rule, provides defaults, and prompts again if the user input is invalid.
    """
    while True:
        try:
            # Prompts the user to enter a priority number, strips leading/trailing whitespace from the input string, and stores it in prio_str.
            prio_str = input("Priority (1+): ").strip() 
            # If prio_str is a positive integer (.isdigit() and > 0), converts it to an int and stores it in prio. Otherwise (blank or invalid), 
            # defaults to 1.
            prio = int(prio_str) if prio_str.isdigit() and int(prio_str) > 0 else 1 
            # Checks if the chosen priority is greater than the maximum allowed value (one more than the current number of rules). 
            # If so, prints a message and restarts input for this rule (via continue).
            if prio > num_rules + 1: 
                print(f"Priority cannot exceed {num_rules + 1}.")
                continue
            # Ask the user for rule direction, strips spaces and converts to lowercase. 
            # If user provides nothing, defaults to "both".
            direction = input("Direction [in/out/both] (default: both): ").strip().lower() or "both" 
            # Validates that the entered direction is one of the allowed values. 
            # If not, prints an error and restarts input for this rule.
            if direction not in ['in', 'out', 'both']: 
                print("Invalid direction. Enter 'in', 'out', or 'both'.")
                continue
            # Prompts user for an IP address or IP range, strips spaces, and stores the result as ipr.
            ipr = input("Source IP/Range (e.g., 1.1.1.1 or 0.0.0.0-255.255.255.255): ").strip() 
            # If the IP field was left blank, prints an error and restarts input for this rule.
            if not ipr: 
                print("IP range is required.")
                continue
            # Calls the parse_ip_range function (explained previously), which returns a tuple representing start and end IPs for use in the rule.
            ip_range = parse_ip_range(ipr) 
            # Prompts for the destination port, strips whitespace, and stores as dport_str.
            dport_str = input("Destination Port (* for any) (default: any): ").strip() 
            # If the user leaves the port blank or enters "*", sets port_val to None (meaning "any port"). 
            if dport_str == '': # Blank
                port_val = None
            elif dport_str == '*': # *
                port_val = None
            # check the input made up entirely of numbers. (prevents parsing invalid input like 'abc'). 
            # Verify the value is within the valid TCP/UDP port range (0–65535)
            elif dport_str.isdigit() and 0 <= int(dport_str) < 65536:
                port_val = int(dport_str)
            else:
                # If the user enters a valid port number (0–65535), converts and stores it. 
                # Otherwise, prints an error and restarts input for this rule.
                print("Invalid port.") 
                continue
            # Prompt for protocol, strips spaces, converts to uppercase. Defaults to "ANY" if blank.
            proto_str = input("Protocol [TCP/UDP/ANY] (default: ANY): ").strip().upper() or "ANY" 
            # Convert proto_str to the corresponding Protocol enum value. Defaults to Protocol.ANY if unmatched.
            proto_val = Protocol(proto_str) if proto_str in Protocol.__members__ else Protocol.ANY 
            # Prompt for action, strips and lowercases user input. Defaults to "deny" if blank.
            action = input("Action [allow/deny] (default: deny): ").strip().lower() or "deny" 
            # Check if action is valid. If not, prints error and restarts input.
            if action not in ['allow', 'deny']: 
                print("Invalid action. Enter 'allow' or 'deny'.")
                continue
            # Print the values entered by the user for review and confirmation
            print("Review your entries:")
            print(f" Priority: {prio}")
            print(f" Direction: {direction}")
            print(f" IP Range: {ipr}")
            print(f" Destination Port: {dport_str if dport_str else '*'}")
            print(f" Protocol: {proto_str}")
            print(f" Action: {action}")
            # Prompts the user: "Confirm creation? (Y/N): " Strips leading/trailing whitespace from the response. 
            # Converts the response to lowercase. 
            # Checks if the response is exactly 'y'. If the user types 'y', it means they want to proceed.
            if input("Confirm creation? (Y/N): ").strip().lower() == 'y': 
                return prio, direction, ip_range, port_val, proto_val, action 
                """
                If the condition above is True ('y' entered), returns a tuple with all the input values collected for the rule:
                prio (priority)
                direction
                ip_range (as a tuple)
                port_val
                proto_val
                action
                This allows the calling code to use these validated fields to create a new rule.
                """
            else:
                # If the user does not type 'y', prints a message to inform that rule creation is canceled. 
                # Returns control to the input loop so the user can start the rule entry process again.
                print("Rule creation cancelled. Returning to field input.") 
        # If any error is thrown during input parsing (for example, invalid conversion or missing data), it: Catches the exception as e
        except Exception as e: 
            # Prints an error message, including details from the exception.
            print("Error parsing fields:", e) 

# Firewall CLI menu driven interface
def firewall_cli():
    fw = Firewall()
    menu = """

    This code provides an interactive menu for the firewall, lets the user manage rules and test packets, handles all meaningful edge cases, 
    catches errors, and guides the user with prompts and explanations.

=== Firewall CLI ===
1. Add Rule
2. Remove Rule
3. Modify Rule
4. List Rules
5. Test Packet
6. Shutdown Firewall
Choose an option: """
    # Start an infinite loop so the program keeps prompting the user for actions until explicitly exited.
    while True: 
        # Display the menu (a string variable named menu that lists options) and collect user input. 
        # .strip() removes any leading/trailing whitespace from the user's entry.
        choice = input(menu).strip() 
        # Start a match-case block (Python 3.10+ feature, acts like switch/case). 
        # The user's choice is compared to possible options.
        match choice: 
            case '1':  # Add Rule
                # Gather all needed rule fields using get_rule_fields, passing the current number of rules for validation.
                fields = get_rule_fields(len(fw.rules)) 
                # Create a new FirewallRule by unpacking collected fields.
                rule = FirewallRule(*fields) 
                # Add this new rule to the firewall (fw.add_rule).
                fw.add_rule(rule) 
                # Print a confirmation message.
                print("Rule added.") 
            case '2':  # Remove Rule
                try:
                    prio = int(input("Remove rule with priority: ")) # Prompt the user for a priority number to remove.
                    if fw.remove_rule(prio): # Try to remove the rule with that priority (fw.remove_rule(prio)).
                        print("Rule removed.") #Print whether a rule was removed or not found.
                    else:
                        print("No rule found with that priority.")
                except ValueError:
                    print("Invalid input.") # If user input can't be converted to an integer, print an error.
            # Modify Rule, includes priority edit/move
            case '3':  
                try:
                    # Prompt for the rule priority to modify and which field to change.
                    prio = int(input("Modify rule with priority: ")) 
                    # Field-specific set of input checks/logic using chained if/elif/else blocks...)
                    field = input("Field to modify [priority/direction/src_ip_range/dport/protocol/action]: ").strip() 
                    # Check whether the field the user wants to change is 'priority'. 
                    # Only executes the following lines if this condition is True.
                    if field == 'priority': 
                        # Prompt the user to enter a new priority value for the rule. 
                        # The prompt tells the user the allowed range (from 1 to the current number of rules) and that the default is 1. 
                        # .strip() removes any leading/trailing whitespace from the input. Stores the result as a string in value_str.
                        value_str = input("New priority (1-number of rules, default 1): ").strip() 
                        # Input validation and default: If the user provided input (value_str) is made up of digits and when converted to integer is greater than 0: 
                        # Convert it to an integer and use it as the new priority value. Otherwise (e.g., blank input or a non-digit), uses 1 as the default value.
                        value = int(value_str) if value_str.isdigit() and int(value_str) > 0 else 1 
                        # Check if the resulting value is less than 1 or greater than the total number of rules in the firewall (len(fw.rules)).  
                        if value < 1 or value > len(fw.rules): 
                            # If so, prints an error message: "Priority out of bounds."
                            print("Priority out of bounds.") 
                            # The continue statement restarts the surrounding loop, re-prompting the user for input (so the user can try again).
                            continue 
                    # Check if the user selected "src_ip_range" as the field to modify. 
                    # If so, executes the following statements.
                    elif field == 'src_ip_range': 
                        # Prompt the user: "New IP/Range: "Reads the input from the user and removes any leading/trailing whitespace. 
                        # The response is stored in the variable ipr.
                        ipr = input("New IP/Range: ").strip() 
                        # Check whether ipr is an empty string (i.e., the user left the input blank).
                        if not ipr: 
                            # If so, prints the message: "IP range is required."
                            print("IP range is required.") 
                            # Use continue to restart the input loop so the user can try again.
                            continue 
                        # Call the parse_ip_range function, passing the ipr variable as its argument. 
                        # ipr is expected to be a string representing either a single IP (e.g., "192.168.1.1") or an IP range (e.g., "192.168.1.1-192.168.1.10"). 
                        # This function processes ipr and returns a tuple: If ipr is a single IP, the tuple is (ip, ip) where both are IPv4Address objects. 
                        # If ipr is a range, the tuple is (start_ip, end_ip), both as IPv4Address objects. 
                        # Assigns the result of the function call to the variable value. 
                        # value now holds the parsed IP or range, which can be stored in a firewall rule for further use.
                        value = parse_ip_range(ipr) 
                    # Checks if the field the user wants to modify is 'dport' (destination port).
                    elif field == 'dport': 
                        # Prompt the user to input a new port number. The prompt tells the user they can use '*' or leave it blank for "any port" (no restriction). 
                        # Uses .strip() to remove any leading or trailing spaces from the input and stores it in dport_str.
                        dport_str = input("New Destination Port (* for any, default any): ").strip() 
                        # If the user's input is blank ('') or exactly an asterisk ('*'):
                        if dport_str == '' or dport_str == '*': 
                            # Set value to None — which means the rule matches any destination port.
                            value = None 
                        else:
                            # Convert the string provided by the user (dport_str) to an integer using the built-in int() function. 
                            # Assigns this integer to the variable value. 
                            # Sets the destination port of the firewall rule to whatever number the user typed.
                            value = int(dport_str) 
                    # Check if the user wants to modify the 'protocol' field. 
                    # Execute the next lines if this is the case.
                    elif field == 'protocol': 
                        proto_str = input("New Protocol [TCP/UDP/ANY] (default: ANY): ").strip().upper() or "ANY"
                        # Prompts the user for a new protocol, offering allowed options and a default: If the user presses Enter (blank input), defaults to "ANY". 
                        # .strip() removes any extra spaces from the input. .upper() converts the input to uppercase to ensure case-insensitive matching. 
                        # or "ANY" ensures that if blank input is provided, proto_str will be "ANY".
                        value = Protocol(proto_str) if proto_str in Protocol.__members__ else Protocol.ANY 
                    # Check if the field being modified is 'direction'. If true, executes the following indented block.
                    elif field == 'direction': 
                        # Prompts the user for a new direction, explaining that 'both' is the default. 
                        # .strip() removes extra whitespace from the input. 
                        # .lower() converts the input to lowercase for consistent comparison (accepts IN, In, etc.). 
                        # If the user provides nothing (just presses Enter), or "both" sets the value to "both".
                        value = input("New value for direction (default: both): ").strip().lower() or "both" 
                        # Checks if what the user entered is a valid direction ('in', 'out', or 'both').
                        if value not in ['in', 'out', 'both']: 
                            # If not, prints an error message: "Invalid direction."
                            print("Invalid direction.") 
                            # continue re-starts the loop, letting the user try again.
                            continue 
                    # Check if the user selected the 'action' field to update. 
                    # If true, the next lines execute.
                    elif field == 'action': 
                        # Prompts the user to input a new action value, indicating 'deny' is the default. 
                        # .strip() removes extra whitespace. 
                        # .lower() converts the input to lowercase, allowing user to enter ALLOW, Allow, etc. 
                        # If user presses Enter (blank), or "deny" sets value to 'deny'.
                        value = input("New value for action (default: deny): ").strip().lower() or "deny" 
                        # Check if the user entered either 'allow' or 'deny'.
                        if value not in ['allow', 'deny']: 
                            # If not, prints error message "Invalid action."
                            print("Invalid action.") 
                            # continue restarts the loop, letting user try again.
                            continue 
                    # This block runs if the field name entered does not match any expected field names 
                    # ('priority', 'direction', 'src_ip_range', 'dport', 'protocol', 'action').
                    else: 
                        # Prints error message "Unknown field."
                        print("Unknown field.") 
                        # Uses continue to restart the input process, allowing for correction.
                        continue 
                    # Calls the modify_rule method on the fw (Firewall) object. 
                    # Passes in the desired rule's priority (prio), field to change (field), and new value (value). 
                    # If modify_rule returns True, it means the modification was successful and the next indented line runs.
                    if fw.modify_rule(prio, field, value): 
                        print("Rule modified.")
                    # If modify_rule returned False, prints an error message indicating: 
                    # The rule was not found, The field did not exist, Or the value provided was invalid.
                    else: 
                        print("Rule/field not found or invalid value.")
                # Catches any exception that occurs during the modification attempt. 
                # Prints an error message with the details of the exception (e). 
                # Ensures the program doesn't crash and gives feedback for troubleshooting.
                except Exception as e: 
                    print("Error:", e)
            # List Rules
            case '4':  
                # Calls the list_rules method defined in the Firewall class. This method prints out all rules in the firewall object 
                fw.list_rules() 
            # Test Packet for rule verification
            case '5':  
                try:
                    # Prompts user to specify packet direction (in or out). 
                    # Removes leading/trailing spaces (.strip()), makes input lowercase (.lower()). 
                    # If user enters nothing (blank), defaults to "both".
                    direction = input("Packet direction [in/out] (default: both): ").strip().lower() or "both" 
                    # Prompts for packet's source IP address (e.g., 192.168.1.1). 
                    # Removes any extra spaces.
                    ip = input("Packet source IP: ").strip() 
                    # Prompts for packet destination port. Strips whitespace. 
                    # User can leave it blank or enter * to mean "any port".
                    dport_str = input("Packet destination port (default: any): ").strip() 
                    # If user input for port is blank or *, sets dport to None (meaning "any port"). 
                    # Otherwise, converts input to an integer for the specific port.
                    dport = None if not dport_str or dport_str == '*' else int(dport_str) 
                    # Prompts for protocol (either TCP or UDP). Strips whitespace and converts input to uppercase. 
                    #  to "ANY" if left blank.
                    proto = input("Packet protocol [TCP/UDP] (default: ANY): ").strip().upper() or "ANY" 
                    # Calls the firewall's packet_action method, passing the gathered parameters. 
                    # This method checks all rules and returns either 'allow' or 'deny' based on the match.
                    verdict = fw.packet_action(direction, ip, dport, proto) 
                    # Prints out the result of the firewall check, showing whether the packet would be allowed or denied.
                    print(f"Packet verdict: {verdict}") 
                # Catches any error that occurred in the block (e.g., invalid IP, bad port).
                except Exception as e: 
                    # Prints an error message with details for troubleshooting.
                    print("Error:", e) 
            # Exit program
            case '6':  
                print("Firewall shutting down.")
                # sys.exit() is a function that terminates the program immediately.
                sys.exit(0) 
            # case _: is the default or "catch-all" case.
            case _: 
                print("Unknown choice.")

if __name__ == "__main__":
    firewall_cli()

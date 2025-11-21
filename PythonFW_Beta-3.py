import ipaddress  # Official IPv4 library: https://docs.python.org/3/library/ipaddress.html
import enum       # Enums for protocol: https://docs.python.org/3/library/enum.html
import sys        # Program exit: https://docs.python.org/3/library/sys.html
from typing import List  # Type hints: https://docs.python.org/3/library/typing.html

"""
Conceptual understanding of topics with referrnces:

Let's highlight and explain sections of deeper conceptual significance in your code—those that require fundamental understanding beyond just syntax. For each, I’ll explain why the concept is "deep" and provide references so you can build a thorough conceptual framework:
________________________________________
1. Enumerations (enum.Enum)
python
class Protocol(enum.Enum):
    TCP = 'TCP'
    UDP = 'UDP'
    ANY = 'ANY'
•	Key Concept: Python's Enum type.
•	Why it’s deep:
•	Enums provide symbolic names for sets of values, enabling safer and more readable code when handling options like protocols.
•	They help prevent bugs caused by typos and make it easy to compare by identity.
•	Using enums means your code can use Protocol.TCP instead of the string 'TCP', which is better for type-checking and refactoring.
•	References:
•	Python Enum documentation
•	Fluent Python: Enums and IntEnum
________________________________________
2. Type Hints & Generics
python
from typing import List
...
self.rules: List[FirewallRule] = []
•	Key Concepts: Type hinting, generics.
•	Why it’s deep:
•	Type hints help with code readability, static analysis, and error prevention—especially important in large codebases.
•	Generics like List[FirewallRule] communicate that the list should only hold FirewallRule objects, enforcing type discipline.
•	This directly impacts maintainability and integration with tools like mypy.
•	References:
•	PEP 484 – Type hints
•	Python typing module
•	Real Python: Python Type Checking
________________________________________
3. Object-Oriented Programming (OOP) Foundations
python
class FirewallRule:
    def __init__(self, ...): ...
    def matches(self, ...): ...
python
class Firewall:
    def __init__(self): ...
    def add_rule(self, ...): ...
    def remove_rule(self, ...): ...
    def modify_rule(self, ...): ...
    def list_rules(self): ...
    def packet_action(self, ...): ...
•	Key Concepts: Classes, encapsulation, methods, constructor (__init__).
•	Why it’s deep:
•	The design uses encapsulation to keep rule-handling logic inside objects.
•	Methods like matches, add_rule, and modify_rule show separation of concerns—each class does a specific job.
•	References:
•	Python Classes and Object Orientation
•	Python Methods and Self
________________________________________
4. Data Structures: Lists, Insertion, and Sorting
python
while idx < len(self.rules) and self.rules[idx].priority < rule.priority:
    idx += 1
self.rules.insert(idx, rule)
for i in range(len(self.rules)):
    self.rules[i].priority = i + 1
•	Key Concepts: List insertion, sorting, iteration.
•	Why it’s deep:
•	Manipulating order in lists to maintain sorted priorities is central to algorithms.
•	Understanding list insertion and the difference between stable and unstable sorting helps prevent subtle bugs.
•	This is an application of fundamental data structure handling that goes beyond just appending.
•	References:
•	Python Lists
•	Python Sorting
•	CS50 Data Structures Video (YouTube)
________________________________________
5. Parsing & Validation with Standard Libraries
python
ip = ipaddress.IPv4Address(ip_str)
•	Key Concepts: Input validation, robust parsing, exceptions.
•	Why it’s deep:
•	Correctly parsing, validating, and using user input is essential for secure and bug-free applications.
•	Many beginner bugs come from treating strings and numbers or IP addresses without proper type checks.
•	References:
•	Python ipaddress
•	Exceptions and error handling
________________________________________
6. Lambda Expressions, Sorting, and Key Functions
python
for r in sorted(self.rules, key=lambda x: x.priority):
•	Key Concepts: Lambda expressions, sorting with key functions.
•	Why it’s deep:
•	Lambdas are anonymous functions often used for transforming or filtering data efficiently.
•	The key= argument in sorting lets you sort complex objects by any attribute, not just numeric or lexical ordering.
•	References:
•	Sorting HOW TO
•	Python lambda expressions
________________________________________
7. String Formatting for Tables
python
print(f"{r.priority:<8} {r.action:<7} ...")
•	Key Concepts: f-strings, alignment and formatting.
•	Why it’s deep:
•	Mastery of f-strings and alignment helps present data clearly and professionally in CLI or logs.
•	Custom formatting is essential for any reporting, logging, or user display task.
•	References:
•	PEP 498: f-strings
•	String formatting mini-language
________________________________________
8. Conditional Logic for Validation and Defaults
python
prio = int(prio_str) if prio_str.isdigit() and int(prio_str) > 0 else 1
...
direction = input(...).strip().lower() or "both"
•	Key Concepts: Short-circuiting logic, default values, input validation.
•	Why it’s deep:
•	The design uses short-circuit logic to safely fallback to defaults.
•	This is an advanced use of conditional logic for robust, user-friendly applications.
•	References:
•	Python Boolean operations
•	Designing for user input & validation
________________________________________
To summarize:
Sections that use Enum, type hints, OOP, data structure logic, parsing/validation, sorting with lambdas, string formatting, and advanced conditional checking all demand deeper conceptual understanding. See the provided references (Python docs, Real Python, CS50, etc.) for curated foundational material.



"""


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
    def __init__(self, priority: int, direction: str, src_ip_range, dport, protocol: Protocol, action: str):
        self.priority = priority
        self.direction = direction
        self.src_ip_range = src_ip_range
        self.dport = dport
        self.protocol = protocol
        self.action = action

    def matches(self, direction, ip, dport, protocol):
        """Packet matching. See: https://docs.python.org/3/library/ipaddress.html
            Each line performs a specific check (direction, IP range, port, protocol). If the packet fails any check, it immediately returns False. If all checks pass, it returns True—this packet matches the rule.
        """
        if self.direction != 'both' and direction != self.direction: # Checks if the rule is for a specific direction: If the rule’s direction is not 'both', then the packet’s direction must match the rule’s direction exactly. If the packet’s direction doesn’t match, return False (no match).
            return False
        start_ip, end_ip = self.src_ip_range # Unpacks the rule’s source IP range into start_ip and end_ip variables for comparison.
        if not (start_ip <= ip <= end_ip): # Checks if the packet's IP falls within the rule’s IP range: If it’s outside the range, return False.
            return False
        if self.dport is not None and self.dport != dport: # Checks the destination port: If the rule specifies a particular port (self.dport is not None), Then the packet’s port must match. Otherwise, return False.
            return False
        if self.protocol != Protocol.ANY and self.protocol != protocol: # Checks the protocol type: If the rule specifies a particular protocol (not 'ANY'), The packet’s protocol must match. Otherwise, return False.
            return False
        return True # If all the above checks pass: The packet matches this rule; indicate success by returning True.

class Firewall:
    """
    Maintains and manipulates ordered list of FirewallRule. See: https://docs.python.org/3/tutorial/datastructures.html
    """
    def __init__(self):
        self.rules: List[FirewallRule] = [] # Creates an instance variable named rules for the Firewall class

    def add_rule(self, rule: FirewallRule):
        """Insert rule in priority order; renumber all. See: https://docs.python.org/3/tutorial/datastructures.html#more-on-lists
            This code finds the correct index to insert a new rule so that the list stays ordered by priority, inserts it, and then renumbers all priorities to eliminate gaps or duplicates.
        """
        idx = 0 # Initializes a counter (idx) to zero. This counter will represent the index position in the rules list where the new rule should be inserted.
        while idx < len(self.rules) and self.rules[idx].priority < rule.priority: # Loops through the existing rules in priority order: Continues as long as idx is less than the number of rules (len(self.rules)). Also checks that the rule at position idx has a priority lower than the new rule's priority. Purpose: Finds the correct spot to insert the new rule so that the list remains sorted by priority (lower priority numbers come first). Increments idx each time until a rule with an equal or higher priority is found or the end of the list is reached.
            idx += 1
        self.rules.insert(idx, rule) # Inserts the new rule at the position idx. Moves all existing rules at and after this index one spot further down the list.
        for i in range(len(self.rules)): # Renumbers all the rules so that priorities are consecutive integers starting from 1. Loops over each rule (by index) in the list. Sets each rule’s priority to its position in the list plus one (so first rule is priority 1, second is 2, etc). Purpose: Keeps priority numbers unique and sequential after insertion.
            self.rules[i].priority = i + 1

    def remove_rule(self, priority):
        """Remove rule by priority. See: https://docs.python.org/3/tutorial/datastructures.html#del
            This code searches for a rule by priority; if found, deletes it, then renumbers all remaining rules for sequence, and signals success. If not found, it returns failure.
        """
        for i, rule in enumerate(self.rules): # Loops through the list self.rules using enumerate, which gives both the index (i) and the rule object (rule). This setup lets you know the position of each rule as you look for the matching one.
            if rule.priority == priority: # Checks if the current rule’s priority matches the requested priority (priority variable). If it does, this is the rule the user wants to remove.
                del self.rules[i] # Deletes (removes) the rule at index i from self.rules. The list now has one fewer rule, and all rules after i move one slot up.
                for j in range(len(self.rules)): # After deleting, loops through the (now shorter) rule list. Sets each rule’s priority attribute to its new position, starting with 1 for the first rule. This renumbers the rules to ensure priorities stay unique and sequential (no skips or duplicates).
                    self.rules[j].priority = j + 1
                return True # Returns True immediately after removing and renumbering. This signals to the caller that a rule was found and removed.
        return False # If the loop finishes without finding a rule with the given priority, returns False. This signals that no rule was removed, because the specified priority was not found.

    def modify_rule(self, priority, field, value):
        """
        Update rule field. If field is 'priority', move rule to new priority and renumber so priorities are unique and consecutive.
        See: https://docs.python.org/3/library/functions.html#setattr
        """
        for idx, rule in enumerate(self.rules): # Loops through every rule in self.rules, using enumerate to get both the index (idx) and the rule object (rule).
            if rule.priority == priority: # Checks whether the current rule's priority matches the one you want to modify.
                if field == 'priority': # If the user wants to modify the priority field (i.e., move the rule to a new position in the list):
                    if not isinstance(value, int) or value < 1 or value > len(self.rules): # Makes sure the new priority value is an integer, at least 1, and not greater than the total number of rules. If these conditions aren't met, immediately return False (modification failed).
                        return False  # Value must be in bounds
                    # Remove rule, re-insert at target
                    rule_to_move = self.rules.pop(idx) # Removes the rule from its current position in the list (pop(idx) returns the actual rule object).
                    self.rules.insert(value - 1, rule_to_move) # Inserts the rule object back into the list at the new position. Since list indices start at 0, it does value - 1.
                    for i in range(len(self.rules)): # After moving, renumbers all rules so their .priority attributes match their position in the list, starting at 1.
                        self.rules[i].priority = i + 1
                    return True # Modification complete (priority move succeeded). Returns True.
                else: # If some other field is being modified (not priority):
                    setattr(rule, field, value) # Uses setattr(rule, field, value) to set the chosen field on the rule object.
                    return True # Returns True to signal the modification was successful.
        return False

    """
    This block loops through all firewall rules and prints each one in a neatly aligned table, showing priority, action, direction, IP range, port, and protocol. It ensures single IPs and any-port rules are displayed in a friendly, readable way.
    """
    def list_rules(self):
        """Display all rules. See: https://docs.python.org/3/library/functions.html#print"""
        print("\nPriority  Action   Dir   IP Range                 Port  Proto")
        print("-------------------------------------------------------------")
        for r in self.rules: # This loops through each rule (r) in the firewall’s list of rules (self.rules).
            startip = str(r.src_ip_range[0]) # Extracts the starting IP address from the rule’s source IP range. Converts it to a string for display.
            endip = str(r.src_ip_range[1]) # Extracts the ending IP address from the rule’s source IP range. Converts it to a string for display.
            iprange = f"{startip}-{endip}" if startip != endip else startip # Creates the display string for the IP range: If the startip and endip are different, show as "start-end" (e.g., "192.168.1.1-192.168.1.10"). If they are the same (just a single IP), just show the IP (e.g., "192.168.1.1").
            port = r.dport if r.dport is not None else "*" # Sets the port display value: If the rule's destination port (r.dport) is set (not None), displays its value. If None (meaning "any port"), it displays "*".
            print(f"{r.priority:<8} {r.action:<7} {r.direction:<5} {iprange:<22} {port:<5} {r.protocol.value}") # Prints a formatted line for the rule, including: The rule's priority (r.priority), left-aligned in 8 spaces. The action (r.action, either 'allow'/'deny'), left-aligned 7 spaces. The direction (r.direction, 'in'/'out'/'both'), left-aligned 5 spaces. The IP range display (iprange), left-aligned 22 spaces. The port display (port), left-aligned 5 spaces. The protocol (r.protocol.value; this gives 'TCP', 'UDP', or 'ANY').

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
        ip = ipaddress.IPv4Address(ip_str) # Converts the packet's IP address from a string (ip_str) to an IPv4Address object using the standard Python library (ipaddress.IPv4Address).This enables safe, validated IP comparison and manipulation.
        proto = Protocol(proto_str) if proto_str in Protocol.__members__ else Protocol.ANY # Checks if the protocol string (proto_str) matches one of the defined protocol types in the Protocol enum (TCP, UDP, ANY). If it matches, it creates a Protocol enum object (e.g., Protocol.TCP). If not, it defaults to Protocol.ANY, meaning it will match any protocol.
        for r in sorted(self.rules, key=lambda x: x.priority): # Loops through all rules in the firewall, sorted by the priority attribute in ascending order (lower numbers indicate higher priority). Ensures that rules are checked in proper order, since priority determines which rule takes precedence.

            if r.matches(direction, ip, dport, proto): # Calls the matches method on the rule, passing in the packet’s direction, IP, destination port, and protocol. If the rule matches the packet (i.e., all criteria are satisfied), returns the rule's action ('allow' or 'deny') immediately. This means the first matching rule determines the outcome.
                return r.action
        return 'deny' # If no rule matched the packet as the loop completes, this line returns 'deny'. This means the firewall implements a default-deny policy (i.e., "implicit deny" if none of the rules match the packet).

def parse_ip_range(addr):
    """Parse single IP or range: https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address
        This block checks for a hyphen to distinguish an IP range from a single IP, parses accordingly, and returns either a (start, end) 
        tuple for a range or (ip, ip) for a single IP. Both results are suitable for further comparison and validation.
    """
    if '-' in addr: # Checks if the string addr contains a hyphen (-). This determines whether the input is an IP range (like '10.0.0.1-10.0.0.10') or just a single IP.
        start, end = addr.split('-') # If a hyphen is present, splits the string into two parts: start (before the hyphen) and end (after the hyphen).
        return (ipaddress.IPv4Address(start.strip()), ipaddress.IPv4Address(end.strip())) # Converts both parts to IPv4Address objects using the ipaddress module. strip() removes any extra spaces from each part. Returns a tuple with the start and end IP addresses, representing an IP address range.
    ip = ipaddress.IPv4Address(addr.strip()) # If no hyphen is found, converts the entire addr string to an IPv4Address object (again stripping spaces). This means the input is just a single IP.
    return (ip, ip) # Returns a tuple with the same IP address twice. This standardizes the output so both cases (single IP and range) return a tuple, allowing the rest of the code to always unpack as start_ip, end_ip.

def get_rule_fields(num_rules):
    """Prompt for all rule fields, keeps visible until completion, set defaults if blank.
        This code gets and validates each field for a new firewall rule, provides defaults, and prompts again if the user input is invalid.
    """
    while True:
        try:
            prio_str = input("Priority (1+): ").strip() # Prompts the user to enter a priority number, strips leading/trailing whitespace from the input string, and stores it in prio_str.
            prio = int(prio_str) if prio_str.isdigit() and int(prio_str) > 0 else 1 # If prio_str is a positive integer (.isdigit() and > 0), converts it to an int and stores it in prio. Otherwise (blank or invalid), defaults to 1.
            if prio > num_rules + 1: # Checks if the chosen priority is greater than the maximum allowed value (one more than the current number of rules). If so, prints a message and restarts input for this rule (via continue).
                print(f"Priority cannot exceed {num_rules + 1}.")
                continue
            direction = input("Direction [in/out/both] (default: both): ").strip().lower() or "both" # Asks the user for rule direction, strips spaces and converts to lowercase. If user provides nothing, defaults to "both".
            if direction not in ['in', 'out', 'both']: # Validates that the entered direction is one of the allowed values. If not, prints an error and restarts input for this rule.
                print("Invalid direction. Enter 'in', 'out', or 'both'.")
                continue
            ipr = input("Source IP/Range (e.g., 1.1.1.1 or 0.0.0.0-255.255.255.255): ").strip() # Prompts user for an IP address or IP range, strips spaces, and stores the result as ipr.
            if not ipr: # If the IP field was left blank, prints an error and restarts input for this rule.
                print("IP range is required.")
                continue
            ip_range = parse_ip_range(ipr) # Calls the parse_ip_range function (explained previously), which returns a tuple representing start and end IPs for use in the rule.
            dport_str = input("Destination Port (* for any) (default: any): ").strip() # Prompts for the destination port, strips whitespace, and stores as dport_str.
            if dport_str == '': # If the user leaves the port blank or enters "*", sets port_val to None (meaning "any port"). 
                port_val = None
            elif dport_str == '*':
                port_val = None
            elif dport_str.isdigit() and 0 <= int(dport_str) < 65536:
                port_val = int(dport_str)
            else:
                print("Invalid port.") # If the user enters a valid port number (0–65535), converts and stores it. Otherwise, prints an error and restarts input for this rule.
                continue
            proto_str = input("Protocol [TCP/UDP/ANY] (default: ANY): ").strip().upper() or "ANY" # Prompts for protocol, strips spaces, converts to uppercase. Defaults to "ANY" if blank.
            proto_val = Protocol(proto_str) if proto_str in Protocol.__members__ else Protocol.ANY # Converts proto_str to the corresponding Protocol enum value. Defaults to Protocol.ANY if unmatched.
            action = input("Action [allow/deny] (default: deny): ").strip().lower() or "deny" # Prompts for action, strips and lowercases user input. Defaults to "deny" if blank.
            if action not in ['allow', 'deny']: # Checks if action is valid. If not, prints error and restarts input.
                print("Invalid action. Enter 'allow' or 'deny'.")
                continue
            print("Review your entries:")
            print(f" Priority: {prio}")
            print(f" Direction: {direction}")
            print(f" IP Range: {ipr}")
            print(f" Destination Port: {dport_str if dport_str else '*'}")
            print(f" Protocol: {proto_str}")
            print(f" Action: {action}")
            if input("Confirm creation? (Y/N): ").strip().lower() == 'y': # Prompts the user: "Confirm creation? (Y/N): " Strips leading/trailing whitespace from the response. Converts the response to lowercase. Checks if the response is exactly 'y'. If the user types 'y', it means they want to proceed.
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
                print("Rule creation cancelled. Returning to field input.") # If the user does not type 'y', prints a message to inform that rule creation is canceled. Returns control to the input loop so the user can start the rule entry process again.
        except Exception as e: # If any error is thrown during input parsing (for example, invalid conversion or missing data), it: Catches the exception as e
            print("Error parsing fields:", e) # Prints an error message, including details from the exception.

def firewall_cli():
    fw = Firewall()
    menu = """

    This code provides an interactive menu for the firewall, lets the user manage rules and test packets, handles all meaningful edge cases, catches errors, and guides the user with prompts and explanations.

=== Firewall CLI ===
1. Add Rule
2. Remove Rule
3. Modify Rule
4. List Rules
5. Test Packet
6. Shutdown Firewall
Choose an option: """
    while True: # Start an infinite loop so the program keeps prompting the user for actions until explicitly exited.
        choice = input(menu).strip() # Display the menu (a string variable named menu that lists options) and collect user input. .strip() removes any leading/trailing whitespace from the user's entry.
        match choice: # Start a match-case block (Python 3.10+ feature, acts like switch/case). The user's choice is compared to possible options.
            case '1':  # Add Rule
                fields = get_rule_fields(len(fw.rules)) # Gather all needed rule fields using get_rule_fields, passing the current number of rules for validation.
                rule = FirewallRule(*fields) # Create a new FirewallRule by unpacking collected fields.
                fw.add_rule(rule) # Add this new rule to the firewall (fw.add_rule).
                print("Rule added.") # Print a confirmation message.
            case '2':  # Remove Rule
                try:
                    prio = int(input("Remove rule with priority: ")) # Prompt the user for a priority number to remove.
                    if fw.remove_rule(prio): # Try to remove the rule with that priority (fw.remove_rule(prio)).
                        print("Rule removed.") #Print whether a rule was removed or not found.
                    else:
                        print("No rule found with that priority.")
                except ValueError:
                    print("Invalid input.") # If user input can't be converted to an integer, print an error.
            case '3':  # Modify Rule, now includes priority edit/move
                try:
                    prio = int(input("Modify rule with priority: ")) # Prompt for the rule priority to modify and which field to change.
                    field = input("Field to modify [priority/direction/src_ip_range/dport/protocol/action]: ").strip() # (Then, a field-specific set of input checks/logic using chained if/elif/else blocks...)
                    if field == 'priority': # Checks whether the field the user wants to change is 'priority'. Only executes the following lines if this condition is True.
                        value_str = input("New priority (1-number of rules, default 1): ").strip() # Prompts the user to enter a new priority value for the rule. The prompt tells the user the allowed range (from 1 to the current number of rules) and that the default is 1. .strip() removes any leading/trailing whitespace from the input. Stores the result as a string in value_str.
                        value = int(value_str) if value_str.isdigit() and int(value_str) > 0 else 1 # Input validation and default: If the user provided input (value_str) is made up of digits and when converted to integer is greater than 0: Converts it to an integer and uses it as the new priority value. Otherwise (e.g., blank input or a non-digit), uses 1 as the default value.
                        if value < 1 or value > len(fw.rules): # Checks if the resulting value is less than 1 or greater than the total number of rules in the firewall (len(fw.rules)).  
                            print("Priority out of bounds.") # If so, prints an error message: "Priority out of bounds."
                            continue # The continue statement restarts the surrounding loop, re-prompting the user for input (so the user can try again).
                    elif field == 'src_ip_range': # Checks if the user selected "src_ip_range" as the field to modify. If so, executes the following statements.
                        ipr = input("New IP/Range: ").strip() # Prompts the user: "New IP/Range: "Reads the input from the user and removes any leading/trailing whitespace. The response is stored in the variable ipr.
                        if not ipr: # Checks whether ipr is an empty string (i.e., the user left the input blank).
                            print("IP range is required.") # If so, prints the message: "IP range is required."
                            continue # Uses continue to restart the input loop so the user can try again.
                        value = parse_ip_range(ipr) # Calls the parse_ip_range function, passing the ipr variable as its argument. ipr is expected to be a string representing either a single IP (e.g., "192.168.1.1") or an IP range (e.g., "192.168.1.1-192.168.1.10"). This function processes ipr and returns a tuple: If ipr is a single IP, the tuple is (ip, ip) where both are IPv4Address objects. If ipr is a range, the tuple is (start_ip, end_ip), both as IPv4Address objects. Assigns the result of the function call to the variable value. value now holds the parsed IP or range, which can be stored in a firewall rule for further use.
                    elif field == 'dport': # Checks if the field the user wants to modify is 'dport' (destination port).
                        dport_str = input("New Destination Port (* for any, default any): ").strip() # Prompts the user to input a new port number. The prompt tells the user they can use '*' or leave it blank for "any port" (no restriction). Uses .strip() to remove any leading or trailing spaces from the input and stores it in dport_str.
                        if dport_str == '' or dport_str == '*': # If the user's input is blank ('') or exactly an asterisk ('*'):
                            value = None # Sets value to None—which means the rule matches any destination port.
                        else:
                            value = int(dport_str) # Converts the string provided by the user (dport_str) to an integer using the built-in int() function. Assigns this integer to the variable value. Effectively, this sets the destination port of the firewall rule to whatever number the user typed.
                    elif field == 'protocol': # Checks if the user wants to modify the 'protocol' field. Executes the next lines if this is the case.
                        proto_str = input("New Protocol [TCP/UDP/ANY] (default: ANY): ").strip().upper() or "ANY"
                        value = Protocol(proto_str) if proto_str in Protocol.__members__ else Protocol.ANY # Prompts the user for a new protocol, offering allowed options and a default: If the user presses Enter (blank input), defaults to "ANY". .strip() removes any extra spaces from the input. .upper() converts the input to uppercase to ensure case-insensitive matching. or "ANY" ensures that if blank input is provided, proto_str will be "ANY".
                    elif field == 'direction': # Checks if the field being modified is 'direction'. If true, executes the following indented block.
                        value = input("New value for direction (default: both): ").strip().lower() or "both" # Prompts the user for a new direction, explaining that 'both' is the default. .strip() removes extra whitespace from the input. .lower() converts the input to lowercase for consistent comparison (accepts IN, In, etc.). If the user provides nothing (just presses Enter), or "both" sets the value to "both".
                        if value not in ['in', 'out', 'both']: # Checks if what the user entered is a valid direction ('in', 'out', or 'both').
                            print("Invalid direction.") # If not, prints an error message: "Invalid direction."
                            continue # continue re-starts the loop, letting the user try again.
                    elif field == 'action': # Checks if the user selected the 'action' field to update. If true, the next lines execute.
                        value = input("New value for action (default: deny): ").strip().lower() or "deny" # Prompts the user to input a new action value, indicating 'deny' is the default. .strip() removes extra whitespace. .lower() converts the input to lowercase, allowing user to enter ALLOW, Allow, etc. If user presses Enter (blank), or "deny" sets value to 'deny'.
                        if value not in ['allow', 'deny']: # Checks if the user entered either 'allow' or 'deny'.
                            print("Invalid action.") # If not, prints error message "Invalid action."
                            continue # continue restarts the loop, letting user try again.
                    else: # This block runs if the field name entered does not match any expected field names ('priority', 'direction', 'src_ip_range', 'dport', 'protocol', 'action').
                        print("Unknown field.") # Prints error message "Unknown field."
                        continue # Uses continue to restart the input process, allowing for correction.
                    if fw.modify_rule(prio, field, value): # Calls the modify_rule method on the fw (Firewall) object. Passes in the desired rule's priority (prio), field to change (field), and new value (value). If modify_rule returns True, it means the modification was successful and the next indented line runs.
                        print("Rule modified.")
                    else: # If modify_rule returned False, prints an error message indicating: The rule was not found, The field did not exist, Or the value provided was invalid.
                        print("Rule/field not found or invalid value.")
                except Exception as e: # Catches any exception that occurs during the modification attempt. Prints an error message with the details of the exception (e). Ensures the program doesn't crash and gives feedback for troubleshooting.
                    print("Error:", e)
            case '4':  # List Rules
                fw.list_rules() # Calls the list_rules method defined in the Firewall class. This method prints out all rules in the firewall object, 
            case '5':  # Test Packet
                try:
                    direction = input("Packet direction [in/out] (default: both): ").strip().lower() or "both" # Prompts user to specify packet direction (in or out). Removes leading/trailing spaces (.strip()), makes input lowercase (.lower()). If user enters nothing (blank), defaults to "both".
                    ip = input("Packet source IP: ").strip() # Prompts for packet's source IP address (e.g., 192.168.1.1). Removes any extra spaces.
                    dport_str = input("Packet destination port (default: any): ").strip() # Prompts for packet destination port. Strips whitespace. User can leave it blank or enter * to mean "any port".
                    dport = None if not dport_str or dport_str == '*' else int(dport_str) # If user input for port is blank or *, sets dport to None (meaning "any port"). Otherwise, converts input to an integer for the specific port.
                    proto = input("Packet protocol [TCP/UDP] (default: ANY): ").strip().upper() or "ANY" # Prompts for protocol (either TCP or UDP). Strips whitespace and converts input to uppercase. Defaults to "ANY" if left blank.
                    verdict = fw.packet_action(direction, ip, dport, proto) # Calls the firewall's packet_action method, passing the gathered parameters. This method checks all rules and returns either 'allow' or 'deny' based on the match.
                    print(f"Packet verdict: {verdict}") # Prints out the result of the firewall check, showing whether the packet would be allowed or denied.
                except Exception as e: # Catches any error that occurred in the block (e.g., invalid IP, bad port).
                    print("Error:", e) # Prints an error message with details for troubleshooting.
            case '6':  # Exit
                print("Firewall shutting down.")
                sys.exit(0) # sys.exit() is a function that terminates the program immediately.
            case _: # case _: is the default or "catch-all" case.
                print("Unknown choice.")

if __name__ == "__main__":
    firewall_cli()

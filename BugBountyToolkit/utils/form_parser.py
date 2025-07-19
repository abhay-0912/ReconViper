"""
Form Parser Module
Provides functionality to parse HTML forms and extract input fields
"""

import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class FormParser:
    """HTML form parser for web security testing"""
    
    def __init__(self):
        """Initialize form parser"""
        self.forms = []
    
    def parse_forms(self, html_content, base_url):
        """
        Parse HTML content and extract form information
        
        Args:
            html_content (str): HTML content to parse
            base_url (str): Base URL for resolving relative form actions
            
        Returns:
            list: List of form dictionaries
        """
        forms = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            form_elements = soup.find_all('form')
            
            for form in form_elements:
                form_data = self._extract_form_data(form, base_url)
                if form_data:
                    forms.append(form_data)
        
        except Exception as e:
            print(f"Error parsing forms: {e}")
        
        return forms
    
    def _extract_form_data(self, form_element, base_url):
        """
        Extract data from a single form element
        
        Args:
            form_element: BeautifulSoup form element
            base_url (str): Base URL for resolving relative URLs
            
        Returns:
            dict: Form data dictionary
        """
        try:
            # Get form attributes
            action = form_element.get('action', '')
            method = form_element.get('method', 'GET').upper()
            enctype = form_element.get('enctype', 'application/x-www-form-urlencoded')
            
            # Resolve relative action URLs
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url
            
            # Extract input fields
            inputs = self._extract_inputs(form_element)
            
            # Extract select fields
            selects = self._extract_selects(form_element)
            
            # Extract textarea fields
            textareas = self._extract_textareas(form_element)
            
            # Combine all input types
            all_inputs = inputs + selects + textareas
            
            form_data = {
                'action': action,
                'method': method,
                'enctype': enctype,
                'inputs': all_inputs,
                'raw_html': str(form_element)
            }
            
            return form_data
        
        except Exception as e:
            print(f"Error extracting form data: {e}")
            return None
    
    def _extract_inputs(self, form_element):
        """
        Extract input elements from form
        
        Args:
            form_element: BeautifulSoup form element
            
        Returns:
            list: List of input field dictionaries
        """
        inputs = []
        input_elements = form_element.find_all('input')
        
        for input_elem in input_elements:
            input_data = {
                'tag': 'input',
                'type': input_elem.get('type', 'text'),
                'name': input_elem.get('name', ''),
                'value': input_elem.get('value', ''),
                'placeholder': input_elem.get('placeholder', ''),
                'required': input_elem.has_attr('required'),
                'disabled': input_elem.has_attr('disabled'),
                'readonly': input_elem.has_attr('readonly'),
                'maxlength': input_elem.get('maxlength', ''),
                'pattern': input_elem.get('pattern', ''),
                'autocomplete': input_elem.get('autocomplete', '')
            }
            
            # Only add inputs with names (for form submission)
            if input_data['name']:
                inputs.append(input_data)
        
        return inputs
    
    def _extract_selects(self, form_element):
        """
        Extract select elements from form
        
        Args:
            form_element: BeautifulSoup form element
            
        Returns:
            list: List of select field dictionaries
        """
        selects = []
        select_elements = form_element.find_all('select')
        
        for select_elem in select_elements:
            # Get options
            options = []
            option_elements = select_elem.find_all('option')
            
            for option in option_elements:
                option_data = {
                    'value': option.get('value', ''),
                    'text': option.get_text(strip=True),
                    'selected': option.has_attr('selected')
                }
                options.append(option_data)
            
            select_data = {
                'tag': 'select',
                'type': 'select',
                'name': select_elem.get('name', ''),
                'value': '',  # Will be set based on selected option
                'multiple': select_elem.has_attr('multiple'),
                'required': select_elem.has_attr('required'),
                'disabled': select_elem.has_attr('disabled'),
                'options': options
            }
            
            # Set default value from selected option
            for option in options:
                if option['selected']:
                    select_data['value'] = option['value']
                    break
            
            if select_data['name']:
                selects.append(select_data)
        
        return selects
    
    def _extract_textareas(self, form_element):
        """
        Extract textarea elements from form
        
        Args:
            form_element: BeautifulSoup form element
            
        Returns:
            list: List of textarea field dictionaries
        """
        textareas = []
        textarea_elements = form_element.find_all('textarea')
        
        for textarea_elem in textarea_elements:
            textarea_data = {
                'tag': 'textarea',
                'type': 'textarea',
                'name': textarea_elem.get('name', ''),
                'value': textarea_elem.get_text(),
                'placeholder': textarea_elem.get('placeholder', ''),
                'required': textarea_elem.has_attr('required'),
                'disabled': textarea_elem.has_attr('disabled'),
                'readonly': textarea_elem.has_attr('readonly'),
                'rows': textarea_elem.get('rows', ''),
                'cols': textarea_elem.get('cols', ''),
                'maxlength': textarea_elem.get('maxlength', '')
            }
            
            if textarea_data['name']:
                textareas.append(textarea_data)
        
        return textareas
    
    def get_form_data_for_submission(self, form_data):
        """
        Prepare form data for HTTP submission
        
        Args:
            form_data (dict): Form data dictionary
            
        Returns:
            dict: Data ready for HTTP submission
        """
        submission_data = {}
        
        for input_field in form_data['inputs']:
            name = input_field['name']
            value = input_field['value']
            input_type = input_field['type']
            
            # Skip certain input types
            if input_type in ['submit', 'button', 'reset', 'file']:
                continue
            
            # Handle different input types
            if input_type == 'checkbox':
                if input_field.get('checked', False):
                    submission_data[name] = value or 'on'
            elif input_type == 'radio':
                if input_field.get('checked', False):
                    submission_data[name] = value
            else:
                submission_data[name] = value
        
        return submission_data
    
    def find_vulnerable_parameters(self, form_data):
        """
        Identify potentially vulnerable form parameters
        
        Args:
            form_data (dict): Form data dictionary
            
        Returns:
            list: List of potentially vulnerable parameters
        """
        vulnerable_params = []
        
        # Parameters that are commonly vulnerable
        vulnerable_names = [
            'search', 'q', 'query', 'keyword', 'term',
            'name', 'username', 'user', 'email',
            'comment', 'message', 'content', 'text',
            'url', 'link', 'redirect', 'return',
            'file', 'path', 'page', 'include',
            'id', 'item', 'product', 'category'
        ]
        
        for input_field in form_data['inputs']:
            name = input_field['name'].lower()
            input_type = input_field['type']
            
            # Check for vulnerable parameter names
            if any(vuln_name in name for vuln_name in vulnerable_names):
                vulnerable_params.append({
                    'name': input_field['name'],
                    'type': input_type,
                    'reason': 'Potentially vulnerable parameter name'
                })
            
            # Check for text inputs (common XSS targets)
            elif input_type in ['text', 'search', 'email', 'url', 'textarea']:
                vulnerable_params.append({
                    'name': input_field['name'],
                    'type': input_type,
                    'reason': 'Text input field'
                })
            
            # Check for hidden inputs with interesting values
            elif input_type == 'hidden' and input_field['value']:
                vulnerable_params.append({
                    'name': input_field['name'],
                    'type': input_type,
                    'reason': 'Hidden input with value'
                })
        
        return vulnerable_params
    
    def generate_form_report(self, forms):
        """
        Generate a report of all forms found
        
        Args:
            forms (list): List of form dictionaries
            
        Returns:
            str: Form analysis report
        """
        report = "FORM ANALYSIS REPORT\n"
        report += "=" * 50 + "\n\n"
        
        if not forms:
            report += "No forms found on the page.\n"
            return report
        
        for i, form in enumerate(forms, 1):
            report += f"Form #{i}\n"
            report += "-" * 20 + "\n"
            report += f"Action: {form['action']}\n"
            report += f"Method: {form['method']}\n"
            report += f"Encoding: {form['enctype']}\n"
            report += f"Input Fields: {len(form['inputs'])}\n\n"
            
            # List input fields
            if form['inputs']:
                report += "Input Fields:\n"
                for input_field in form['inputs']:
                    report += f"  - {input_field['name']} ({input_field['type']})\n"
                report += "\n"
            
            # Check for potentially vulnerable parameters
            vulnerable = self.find_vulnerable_parameters(form)
            if vulnerable:
                report += "Potentially Vulnerable Parameters:\n"
                for param in vulnerable:
                    report += f"  - {param['name']}: {param['reason']}\n"
                report += "\n"
        
        return report


def main():
    """Test form parser functionality"""
    # Sample HTML with forms
    sample_html = """
    <html>
    <body>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search...">
            <input type="submit" value="Search">
        </form>
        
        <form action="/login" method="POST">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="submit" value="Login">
        </form>
        
        <form action="/comment" method="POST">
            <input type="text" name="name" placeholder="Your name">
            <textarea name="comment" rows="4" cols="50" placeholder="Your comment"></textarea>
            <select name="rating">
                <option value="1">1 star</option>
                <option value="5" selected>5 stars</option>
            </select>
            <input type="submit" value="Submit">
        </form>
    </body>
    </html>
    """
    
    parser = FormParser()
    forms = parser.parse_forms(sample_html, "http://example.com")
    
    print(f"Found {len(forms)} forms")
    print("\n" + parser.generate_form_report(forms))


if __name__ == "__main__":
    main()

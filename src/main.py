import streamlit as st
import requests
import json
from typing import Dict
import boto3
from botocore.exceptions import ClientError
import re
import pandas as pd
import os
from boto3.dynamodb.conditions import Attr
import time

# Constants
# API_BASE_URL = "http://0.0.0.0:8000"
API_BASE_URL = st.secrets["API_BASE_URL"]
API_KEY = st.secrets["API_KEY"]
USER_POOL_ID = st.secrets["USER_POOL_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
AWS_REGION = st.secrets["AWS_DEFAULT_REGION"]
S3_BUCKET_NAME = st.secrets["S3_BUCKET_NAME"]
DYNAMODB_TABLE_NAME = st.secrets["DYNAMODB_TABLE_NAME"]

s3_client = boto3.client("s3", region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(DYNAMODB_TABLE_NAME)

ENABLE_LOGIN = True  # Set this to False to disable login functionality


PROFESSOR_CONFIG = {
    "drvinay": {
        "index_name": "drvinay",
        "s3_prefix": "data/pdfs/drvinay/",
    },
    "lewas": {
        "index_name": "lewas",
        "s3_prefix": "data/pdfs/lewas/",
    },
    "historyoftech": {
        "index_name": "historyoftech",
        "s3_prefix": "data/pdfs/historyoftech/",
    },
}

# UI Customization Options
THEMES = {
    "Accessible Light": {
        "bg_color": "#FFFFFF",
        "text_color": "#000000",
        "accent_color": "#1E90FF",  # High contrast accent color
        "font_size": "16px",  # Slightly larger font size for readability
    },
    "Accessible Dark": {
        "bg_color": "#1C1C1C",
        "text_color": "#FFFFFF",
        "accent_color": "#FFD700",  # High contrast accent color
        "font_size": "16px",  # Slightly larger font size for readability
    },
    "Pastel": {
        "bg_color": "#FFF5E6",
        "text_color": "#5D4037",
        "accent_color": "#FF9800",
        "font_size": "16px",  # Slightly larger font size for readability
    },
    "High Contrast": {
        "bg_color": "#000000",
        "text_color": "#FFFFFF",
        "accent_color": "#FF0000",  # Red for strong visual contrast
        "font_size": "18px",  # Larger font size for readability
    },
    "Solarized Light": {
        "bg_color": "#FDF6E3",
        "text_color": "#657B83",
        "accent_color": "#268BD2",
        "font_size": "16px",
    },
    "Solarized Dark": {
        "bg_color": "#002B36",
        "text_color": "#839496",
        "accent_color": "#B58900",
        "font_size": "16px",
    },
}


FONTS = ["Arial", "Roboto", "Helvetica", "Times New Roman", "Courier"]

# Language options
LANGUAGES = {
    "afrikaans": "af",
    "albanian": "sq",
    "amharic": "am",
    "arabic": "ar",
    "armenian": "hy",
    "assamese": "as",
    "aymara": "ay",
    "azerbaijani": "az",
    "bambara": "bm",
    "basque": "eu",
    "belarusian": "be",
    "bengali": "bn",
    "bhojpuri": "bho",
    "bosnian": "bs",
    "bulgarian": "bg",
    "catalan": "ca",
    "cebuano": "ceb",
    "chichewa": "ny",
    "chinese (simplified)": "zh-CN",
    "chinese (traditional)": "zh-TW",
    "corsican": "co",
    "croatian": "hr",
    "czech": "cs",
    "danish": "da",
    "dhivehi": "dv",
    "dogri": "doi",
    "dutch": "nl",
    "english": "en",
    "esperanto": "eo",
    "estonian": "et",
    "ewe": "ee",
    "filipino": "tl",
    "finnish": "fi",
    "french": "fr",
    "frisian": "fy",
    "galician": "gl",
    "georgian": "ka",
    "german": "de",
    "greek": "el",
    "guarani": "gn",
    "gujarati": "gu",
    "haitian creole": "ht",
    "hausa": "ha",
    "hawaiian": "haw",
    "hebrew": "iw",
    "hindi": "hi",
    "hmong": "hmn",
    "hungarian": "hu",
    "icelandic": "is",
    "igbo": "ig",
    "ilocano": "ilo",
    "indonesian": "id",
    "irish": "ga",
    "italian": "it",
    "japanese": "ja",
    "javanese": "jw",
    "kannada": "kn",
    "kazakh": "kk",
    "khmer": "km",
    "kinyarwanda": "rw",
    "konkani": "gom",
    "korean": "ko",
    "krio": "kri",
    "kurdish (kurmanji)": "ku",
    "kurdish (sorani)": "ckb",
    "kyrgyz": "ky",
    "lao": "lo",
    "latin": "la",
    "latvian": "lv",
    "lingala": "ln",
    "lithuanian": "lt",
    "luganda": "lg",
    "luxembourgish": "lb",
    "macedonian": "mk",
    "maithili": "mai",
    "malagasy": "mg",
    "malay": "ms",
    "malayalam": "ml",
    "maltese": "mt",
    "maori": "mi",
    "marathi": "mr",
    "meiteilon (manipuri)": "mni-Mtei",
    "mizo": "lus",
    "mongolian": "mn",
    "myanmar": "my",
    "nepali": "ne",
    "norwegian": "no",
    "odia (oriya)": "or",
    "oromo": "om",
    "pashto": "ps",
    "persian": "fa",
    "polish": "pl",
    "portuguese": "pt",
    "punjabi": "pa",
    "quechua": "qu",
    "romanian": "ro",
    "russian": "ru",
    "samoan": "sm",
    "sanskrit": "sa",
    "scots gaelic": "gd",
    "sepedi": "nso",
    "serbian": "sr",
    "sesotho": "st",
    "shona": "sn",
    "sindhi": "sd",
    "sinhala": "si",
    "slovak": "sk",
    "slovenian": "sl",
    "somali": "so",
    "spanish": "es",
    "sundanese": "su",
    "swahili": "sw",
    "swedish": "sv",
    "tajik": "tg",
    "tamil": "ta",
    "tatar": "tt",
    "telugu": "te",
    "thai": "th",
    "tigrinya": "ti",
    "tsonga": "ts",
    "turkish": "tr",
    "turkmen": "tk",
    "twi": "ak",
    "ukrainian": "uk",
    "urdu": "ur",
    "uyghur": "ug",
    "uzbek": "uz",
    "vietnamese": "vi",
    "welsh": "cy",
    "xhosa": "xh",
    "yiddish": "yi",
    "yoruba": "yo",
    "zulu": "zu",
}
TEACHER_INFO = {
    "drvinay": {
        "description": """
        Dr. Vinay | Physics Professor
        
        Expertise: Classical Physics
        
        Uploaded Notes:
        • Electrostatics
        • Pressure and its measurement
        • Fundamental physics principles
        
        Known for clear explanations and practical examples.
        """,
        "placeholder": "Try: 'Explain the concept of pressure in fluids'",
    },
    "lewas": {
        "description": """
        LEWAS | Learning Enhanced Watershed Assessment System
        
        Interdisciplinary Research Initiative:
        • Engineering Education
        • Civil Engineering
        • Biological Systems Engineering
        • Computer Science
        
        Key Features:
        • Real-time water and weather monitoring
        • Located at Webb Branch, Virginia Tech
        • Monitors flow rate, depth, pH, oxygen, conductivity, temperature
        
        Focus: Water sustainability education and research
        """,
        "placeholder": "Try: 'Explain the functioning of the LEWAS Lab'",
    },
    "historyoftech": {
        "description": """
        History of Technology | Course Overview
        
        Topics Covered:
        • Evolution of human innovation
        • Birth of Personal Computing
        • Rise of Home Video Game Consoles
        
        Course Materials:
        • Comprehensive overview of technology and innovation
        • Deep dives into computing and gaming history
        
        Explore how technology shapes our past, present, and future.
        """,
        "placeholder": "Try: 'Explain the evolution of video game technology'",
    },
}


def apply_custom_css(theme, font):
    st.markdown(
        f"""
    <style>
    .stApp {{
        background-color: {theme['bg_color']};
        color: {theme['text_color']};
    }}
    .stButton>button {{
        background-color: {theme['accent_color']};
        color: {theme['bg_color']};
    }}
    body {{
        font-family: {font}, sans-serif;
    }}
    </style>
    """,
        unsafe_allow_html=True,
    )


def send_query(prompt, teacher_name, target_language):
    try:
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "API-Key": API_KEY,
        }

        # Add the user's authentication token if available
        if "auth_token" in st.session_state:
            headers["Authorization"] = f"Bearer {st.session_state.auth_token}"

        response = requests.post(
            f"{API_BASE_URL}/combined_query",
            json={
                "query_text": prompt,
                "teacher_name": teacher_name,
                "target_language": target_language,
            },
            headers=headers,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"An error occurred: {str(e)}")
        return None


def searchable_dropdown(
    options: Dict[str, str], key: str, default: str = "english"
) -> str:
    container = st.container()
    selected = container.selectbox(
        "Select or type to search",
        options.keys(),
        key=f"{key}_select",
        index=list(options.keys()).index(default),
        format_func=lambda x: x.title(),
    )

    filtered_options = {
        k: v for k, v in options.items() if selected.lower() in k.lower()
    }

    if len(filtered_options) == 1:
        selected = list(filtered_options.keys())[0]
    elif filtered_options:
        selected = container.selectbox(
            "Filtered options",
            filtered_options.keys(),
            key=f"{key}_filtered",
            format_func=lambda x: x.title(),
        )

    return options[selected]


def unauthenticated_main():
    st.title("Educational Query Assistant (Login Disabled for demo)")
    if ENABLE_LOGIN:
        tab1, tab2 = st.tabs(["Sign In", "Sign Up"])
        with tab1:
            sign_in_page()
        with tab2:
            sign_up()
    else:
        authenticated_main()


def sign_up():
    st.subheader("Sign Up")
    email = st.text_input("Email", key="signup_email")
    password = st.text_input("Password", type="password", key="signup_password")
    confirm_password = st.text_input(
        "Confirm Password", type="password", key="signup_confirm_password"
    )
    is_instructor = st.toggle("I am an instructor", key="signup_is_instructor")

    # Password validation
    password_valid = False
    if password:
        length_check = len(password) >= 8
        number_check = re.search(r"\d", password) is not None
        special_char_check = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None
        uppercase_check = re.search(r"[A-Z]", password) is not None
        lowercase_check = re.search(r"[a-z]", password) is not None

        password_valid = all(
            [
                length_check,
                number_check,
                special_char_check,
                uppercase_check,
                lowercase_check,
            ]
        )

        st.markdown(
            """
        <style>
        .password-check {
            margin-bottom: 5px;
        }
        .valid {
            color: green;
        }
        .invalid {
            color: red;
        }
        </style>
        """,
            unsafe_allow_html=True,
        )

        st.markdown(
            f"""
        <div class="password-check {'valid' if length_check else 'invalid'}">
            {'✓' if length_check else '✗'} Minimum 8 characters
        </div>
        <div class="password-check {'valid' if number_check else 'invalid'}">
            {'✓' if number_check else '✗'} Contains at least 1 number
        </div>
        <div class="password-check {'valid' if special_char_check else 'invalid'}">
            {'✓' if special_char_check else '✗'} Contains at least 1 special character
        </div>
        <div class="password-check {'valid' if uppercase_check else 'invalid'}">
            {'✓' if uppercase_check else '✗'} Contains at least 1 uppercase letter
        </div>
        <div class="password-check {'valid' if lowercase_check else 'invalid'}">
            {'✓' if lowercase_check else '✗'} Contains at least 1 lowercase letter
        </div>
        """,
            unsafe_allow_html=True,
        )

    passwords_match = password == confirm_password
    if not passwords_match and confirm_password:
        st.error("Passwords do not match")

    signup_button = st.button(
        "Sign Up",
        key="signup_button",
        disabled=not (password_valid and passwords_match),
    )

    if signup_button:
        try:
            client = boto3.client("cognito-idp", region_name=AWS_REGION)
            response = client.sign_up(
                ClientId=CLIENT_ID,
                Username=email,
                Password=password,
                UserAttributes=[
                    {"Name": "email", "Value": email},
                ],
            )
            st.success(
                "Sign up successful! Please check your email for verification code."
            )
            st.session_state.email = email
            st.session_state.temp_password = password
            st.session_state.temp_is_instructor = (
                is_instructor  # Store this temporarily
            )
            st.rerun()
        except ClientError as e:
            st.error(f"An error occurred: {str(e)}")


def sign_in(email, password):
    try:
        client = boto3.client("cognito-idp", region_name=AWS_REGION)
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": email, "PASSWORD": password},
        )
        st.session_state.authenticated = True
        st.session_state.auth_token = response["AuthenticationResult"]["AccessToken"]

        # Get user attributes to check if they're an instructor
        user_info = client.get_user(AccessToken=st.session_state.auth_token)
        is_instructor = next(
            (
                attr["Value"]
                for attr in user_info["UserAttributes"]
                if attr["Name"] == "custom:is_instructor"
            ),
            "false",
        )
        st.session_state.is_instructor = is_instructor.lower() == "true"

        return True
    except ClientError as e:
        st.error(f"An error occurred during sign in: {str(e)}")
        return False


def instructor_portal():
    st.sidebar.empty()  # Clear the sidebar
    st.title("Instructor Portal")

    # Button to go back to the main page
    if st.button("Back to Main Page"):
        st.session_state.show_instructor_portal = False
        st.rerun()

    # Dropdown to select professor
    professor = st.selectbox("Select Professor", ["drvinay", "lewas", "historyoftech"])

    # File upload
    uploaded_file = st.file_uploader("Choose a file to upload", type=["pdf"])
    if uploaded_file is not None:
        if st.button("Upload File"):
            if upload_to_s3(uploaded_file, professor):
                st.success(f"File {uploaded_file.name} uploaded successfully!")
            else:
                st.error("Failed to upload file. Please try again.")

    # Fetch documents from backend
    documents = fetch_documents(professor)

    # Display documents in a table
    if documents:
        # Remove documents with 0 bytes
        documents = [doc for doc in documents if doc["Size (bytes)"] > 0]

        df = pd.DataFrame(documents)

        # Reorder columns
        df = df[["Document Name", "Upload Date", "Size (bytes)", "Processed"]]

        # Display the table without index
        st.table(df.set_index("Document Name"))

        # Add a button to process all documents
        if st.button("Process All Documents"):
            if trigger_processing(professor):
                st.success(f"Processing triggered for all documents of {professor}")
                st.info("Refreshing page to show updated status...")
                time.sleep(2)  # Give a moment for the user to read the message
                st.rerun()
            else:
                st.error("Failed to trigger processing for all documents")
    else:
        st.write("No documents found for this professor.")

    # Add a refresh button
    if st.button("Refresh Document Status"):
        st.rerun()


def fetch_documents(professor):
    """Main function to fetch documents for the professor page."""
    if professor not in PROFESSOR_CONFIG:
        return []

    documents = get_professor_documents(professor)
    # Sort documents by upload date (newest first)
    documents.sort(key=lambda x: x["Upload Date"], reverse=True)
    return documents


def upload_to_s3(file, professor):
    """Upload a file to S3 for a specific professor."""
    s3_prefix = PROFESSOR_CONFIG[professor]["s3_prefix"]
    s3_key = f"{s3_prefix}{file.name}"
    try:
        s3_client.upload_fileobj(file, S3_BUCKET_NAME, s3_key)
        return True
    except ClientError as e:
        print(f"Error uploading file to S3: {e}")
        return False


def trigger_processing(professor):
    """Trigger the backend API to process all PDFs for a professor."""
    try:
        headers = {
            "accept": "application/json",
            "API-Key": API_KEY,
        }

        # Add the user's authentication token if available
        if "auth_token" in st.session_state:
            headers["Authorization"] = f"Bearer {st.session_state.auth_token}"

        response = requests.post(
            f"{API_BASE_URL}/process_all_pdfs",
            params={"teacher_name": professor},
            headers=headers,
        )
        response.raise_for_status()

        if response.status_code == 200:
            st.success(f"Processing triggered for all documents of {professor}")
            return True
        else:
            st.error(
                f"Failed to trigger processing. Status code: {response.status_code}"
            )
            return False
    except requests.RequestException as e:
        st.error(f"Error triggering document processing: {str(e)}")
        return False


def get_s3_documents(professor):
    """Retrieve documents from S3 for a given professor."""
    s3_prefix = PROFESSOR_CONFIG[professor]["s3_prefix"]
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=s3_prefix)
        documents = []
        for obj in response.get("Contents", []):
            documents.append(
                {
                    "filename": os.path.basename(obj["Key"]),
                    "last_modified": obj["LastModified"],
                    "size": obj["Size"],
                }
            )
        return documents
    except ClientError as e:
        print(f"Error retrieving S3 documents: {e}")
        return []


def get_processed_documents(professor):
    """Retrieve processed documents from DynamoDB for a given professor."""
    try:
        response = table.scan(
            FilterExpression=Attr("teacher").eq(professor),
            ProjectionExpression="filename",
        )
        return {item["filename"] for item in response.get("Items", [])}
    except ClientError as e:
        print(f"Error retrieving processed documents from DynamoDB: {e}")
        return set()


def get_professor_documents(professor):
    """Combine S3 and DynamoDB data to get complete document information."""
    s3_documents = get_s3_documents(professor)
    processed_documents = get_processed_documents(professor)

    combined_documents = []
    for doc in s3_documents:
        combined_documents.append(
            {
                "Document Name": doc["filename"],
                "Upload Date": doc["last_modified"].strftime("%Y-%m-%d %H:%M:%S"),
                "Size (bytes)": doc["size"],
                "Processed": "Yes" if doc["filename"] in processed_documents else "No",
            }
        )

    return combined_documents


def sign_in_page():
    st.subheader("Sign In")
    email = st.text_input("Email", key="signin_email")
    password = st.text_input("Password", type="password", key="signin_password")

    if st.button("Sign In", key="signin_button"):
        if sign_in(email, password):
            st.success("Signed in successfully!")
            st.rerun()


def authenticated_main():
    st.title("Educational Query Assistant (Login Disabled for demo)")

    # Initialize theme and font with default values
    theme_name = "Accessible Dark"
    font = "Arial"

    # Sidebar for customization and user preferences
    with st.sidebar:
        st.subheader("User Settings")
        is_instructor = st.toggle(
            "Instructor Mode", value=st.session_state.get("is_instructor", False)
        )
        st.session_state.is_instructor = is_instructor

        if is_instructor:
            if st.button("Instructor Portal"):
                st.session_state.show_instructor_portal = True
                st.rerun()

        if not st.session_state.get("show_instructor_portal", False):
            st.subheader("Query Settings")

            teacher_name = st.selectbox(
                "Select Teacher",
                list(TEACHER_INFO.keys()),
                format_func=lambda x: x.capitalize(),  # Capitalize the first letter
            )
            if teacher_name:
                st.markdown("### Teacher Information")
                st.markdown(TEACHER_INFO[teacher_name]["description"])
                st.markdown("---")

            # Searchable language dropdown
            st.subheader("Select Output Language")
            target_language = searchable_dropdown(
                LANGUAGES, "backend_language", default="english"
            )

            # Move theme and font selection to the bottom of the sidebar
            st.markdown("---")  # Add a separator
            st.subheader("Appearance Settings", help="Customize the app's look")
            theme_name = st.selectbox(
                "Theme",
                list(THEMES.keys()),
                index=list(THEMES.keys()).index("Accessible Dark"),
            )
            font = st.selectbox("Font", FONTS)

        # Add contact information for issues
        st.sidebar.title("Contact Us")
        st.sidebar.info(
            """
        Is something wrong? Email [lewas.vt@outlook.com](mailto:lewas.vt@outlook.com) or message on 
        [LinkedIn](https://www.linkedin.com/in/dhruvvarshneyvk/).
        """
        )

        # Sign Out button
        st.button("Sign Out", on_click=sign_out)

    # Apply custom CSS
    apply_custom_css(THEMES[theme_name], font)

    # Main content area
    if st.session_state.get("show_instructor_portal", False):
        instructor_portal()
    else:
        # Query input
        prompt = st.text_area(
            "Enter your question:",
            height=100,
            placeholder=TEACHER_INFO[teacher_name]["placeholder"],
        )

        if st.button("Submit Query"):
            if prompt:
                with st.spinner("Processing your query..."):
                    result = send_query(prompt, teacher_name, target_language)

                if result and result.get("status") == "success":
                    st.success("Query processed successfully!")

                    # Display the results
                    st.subheader("Professor's Notes")
                    st.write(result["result"]["Professor's Notes"])

                    st.subheader("Internet Notes (Powered by Tavily)")
                    st.write(result["result"]["Internet Notes"])

                    st.subheader("Cross-Verification and Contradictions")
                    contradictions = result["result"][
                        "Cross-Verification and Contradictions"
                    ]
                    if (
                        contradictions
                        and contradictions.lower() != "no contradictions found."
                    ):
                        st.warning(contradictions)
                    else:
                        st.info("No contradictions found between the sources.")

                    st.subheader("Sources")
                    st.write("Professor's Sources:")
                    for source in result["result"]["Professor's Sources"]:
                        st.write(f"- {source}")

                    st.write("Internet Sources (Powered by Tavily):")
                    for source in result["result"]["Internet Sources"]:
                        st.write(f"- {source}")

                    if result["result"]["Extra Sources"]:
                        st.subheader("Further Reading")
                        for source in result["result"]["Extra Sources"]:
                            st.write(f"- {source}")
                else:
                    st.error("Failed to process query. Please try again.")
            else:
                st.warning("Please enter a query before submitting.")


def update_instructor_status(is_instructor):
    try:
        client = boto3.client("cognito-idp", region_name=AWS_REGION)
        client.update_user_attributes(
            UserAttributes=[
                {"Name": "custom:is_instructor", "Value": str(is_instructor).lower()},
            ],
            AccessToken=st.session_state.auth_token,
        )
        st.session_state.is_instructor = is_instructor
        st.success("Instructor status updated successfully!")
    except ClientError as e:
        st.error(f"Failed to update instructor status: {str(e)}")


def sign_out():
    for key in [
        "authenticated",
        "auth_token",
        "is_instructor",
        "show_instructor_portal",
    ]:
        st.session_state.pop(key, None)
    st.success("Signed out successfully!")
    st.rerun()


def verify():
    st.subheader("Verify Email")
    verification_code = st.text_input("Verification Code", key="verify_code")

    if st.button("Verify", key="verify_button"):
        try:
            client = boto3.client("cognito-idp", region_name=AWS_REGION)
            response = client.confirm_sign_up(
                ClientId=CLIENT_ID,
                Username=st.session_state.email,
                ConfirmationCode=verification_code,
            )
            st.success("Email verified successfully!")

            # Attempt to sign in automatically
            if sign_in(st.session_state.email, st.session_state.temp_password):
                # Set the custom attribute after successful sign-in
                try:
                    client.update_user_attributes(
                        UserAttributes=[
                            {
                                "Name": "custom:is_instructor",
                                "Value": str(
                                    st.session_state.temp_is_instructor
                                ).lower(),
                            },
                        ],
                        AccessToken=st.session_state.auth_token,
                    )
                    st.session_state.is_instructor = st.session_state.temp_is_instructor
                    print(f"Instructor status set to: {st.session_state.is_instructor}")
                except ClientError as e:
                    st.warning(
                        f"User created, but failed to set instructor status: {str(e)}"
                    )

                st.session_state.pop("email", None)
                st.session_state.pop("temp_password", None)
                st.session_state.pop("temp_is_instructor", None)
                st.rerun()
            else:
                st.error(
                    "Verification successful, but automatic sign-in failed. Please sign in manually."
                )
                st.session_state.pop("email", None)
                st.session_state.pop("temp_password", None)
                st.session_state.pop("temp_is_instructor", None)
        except ClientError as e:
            st.error(f"An error occurred: {str(e)}")


def main():
    if ENABLE_LOGIN:
        if "authenticated" not in st.session_state:
            st.session_state.authenticated = False

        if st.session_state.authenticated:
            authenticated_main()
        elif "email" in st.session_state:
            verify()
        else:
            unauthenticated_main()
    else:
        authenticated_main()


if __name__ == "__main__":
    main()

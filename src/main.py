import streamlit as st
import requests
import json
from typing import Dict
import boto3
from botocore.exceptions import ClientError
import re

# Constants
# API_BASE_URL = "http://0.0.0.0:8000"
API_BASE_URL = st.secrets["API_BASE_URL"]
API_KEY = st.secrets["API_KEY"]
USER_POOL_ID = st.secrets["USER_POOL_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
REGION_NAME = st.secrets["REGION_NAME"]

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
    st.title("Educational Query Assistant")
    tab1, tab2 = st.tabs(["Sign In", "Sign Up"])
    with tab1:
        sign_in_page()
    with tab2:
        sign_up()


def sign_up():
    st.subheader("Sign Up")
    email = st.text_input("Email", key="signup_email")
    password = st.text_input("Password", type="password", key="signup_password")
    confirm_password = st.text_input(
        "Confirm Password", type="password", key="signup_confirm_password"
    )

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
            client = boto3.client("cognito-idp", region_name=REGION_NAME)
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
            st.session_state.temp_password = password  # Store password temporarily
            st.experimental_rerun()
        except ClientError as e:
            st.error(f"An error occurred: {str(e)}")


def sign_in(email, password):
    try:
        client = boto3.client("cognito-idp", region_name=REGION_NAME)
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": email, "PASSWORD": password},
        )
        st.session_state.authenticated = True
        st.session_state.auth_token = response["AuthenticationResult"]["IdToken"]
        return True
    except ClientError as e:
        st.error(f"An error occurred during sign in: {str(e)}")
        return False


def sign_in_page():
    st.subheader("Sign In")
    email = st.text_input("Email", key="signin_email")
    password = st.text_input("Password", type="password", key="signin_password")

    if st.button("Sign In", key="signin_button"):
        if sign_in(email, password):
            st.success("Signed in successfully!")
            st.experimental_rerun()


def authenticated_main():
    st.title("Educational Query Assistant")

    # Sidebar for customization
    st.sidebar.title("Customize Your Experience")
    theme_name = st.sidebar.selectbox(
        "Choose a theme",
        list(THEMES.keys()),
        index=list(THEMES.keys()).index("Accessible Dark"),
    )
    font = st.sidebar.selectbox("Choose a font", FONTS)

    # Apply custom CSS
    apply_custom_css(THEMES[theme_name], font)

    # User preferences
    teacher_name = st.selectbox("Select Teacher", ["drvinay", "lewas", "historyoftech"])

    # Searchable language dropdown
    st.subheader("Select Output Language")
    target_language = searchable_dropdown(
        LANGUAGES, "backend_language", default="english"
    )

    # Query input
    prompt = st.text_area("Enter your question:", height=100)

    if st.button("Submit Query"):
        if prompt:
            with st.spinner("Processing your query..."):
                result = send_query(prompt, teacher_name, target_language)

            if result and result.get("status") == "success":
                st.success("Query processed successfully!")

                # Display the results
                st.subheader("Professor's Notes")
                st.write(result["result"]["Professor's Notes"])

                st.subheader("Internet Notes")
                st.write(result["result"]["Internet Notes"])

                st.subheader("Sources")
                st.write("Professor's Sources:")
                for source in result["result"]["Professor's Sources"]:
                    st.write(f"- {source}")

                st.write("Internet Sources:")
                for source in result["result"]["Internet Sources"]:
                    st.write(f"- {source}")

                if result["result"]["Extra Sources"]:
                    st.subheader("Extra Sources")
                    for source in result["result"]["Extra Sources"]:
                        st.write(f"- {source}")
            else:
                st.error("Failed to process query. Please try again.")
        else:
            st.warning("Please enter a query before submitting.")

    if st.sidebar.button("Sign Out"):
        sign_out()


def sign_out():
    st.session_state.authenticated = False
    st.success("Signed out successfully!")
    st.experimental_rerun()


def verify():
    st.subheader("Verify Email")
    verification_code = st.text_input("Verification Code", key="verify_code")

    if st.button("Verify", key="verify_button"):
        try:
            client = boto3.client("cognito-idp", region_name=REGION_NAME)
            response = client.confirm_sign_up(
                ClientId=CLIENT_ID,
                Username=st.session_state.email,
                ConfirmationCode=verification_code,
            )
            st.success("Email verified successfully!")

            # Attempt to sign in automatically
            if sign_in(st.session_state.email, st.session_state.temp_password):
                st.session_state.pop("email", None)
                st.session_state.pop("temp_password", None)
                st.experimental_rerun()
            else:
                st.error(
                    "Verification successful, but automatic sign-in failed. Please sign in manually."
                )
                st.session_state.pop("email", None)
                st.session_state.pop("temp_password", None)
        except ClientError as e:
            st.error(f"An error occurred: {str(e)}")


def main():
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        authenticated_main()
    elif "email" in st.session_state:
        verify()
    else:
        unauthenticated_main()


if __name__ == "__main__":
    main()

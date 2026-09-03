-- 1. PROFILES (Every single person, adult or child, gets a profile)
CREATE TABLE profiles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  auth_user_id UUID REFERENCES auth.users(id), -- Only adults/app users will have this
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT, 
  phone TEXT,
  date_of_birth DATE NOT NULL,
  is_minor BOOLEAN GENERATED ALWAYS AS (age(date_of_birth) < interval '18 years') STORED,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. HOUSEHOLDS / ACCOUNTS (The billing entity)
CREATE TABLE households (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  primary_member_id UUID REFERENCES profiles(id) NOT NULL, -- The person paying
  stripe_customer_id TEXT, -- Link to Stripe or payment processor
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. HOUSEHOLD MEMBERS (Links people to the billing account)
CREATE TABLE household_members (
  household_id UUID REFERENCES households(id),
  profile_id UUID REFERENCES profiles(id),
  role TEXT CHECK (role IN ('Primary', 'Spouse', 'Dependent')),
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (household_id, profile_id)
);

-- 4. RELATIONSHIPS (Crucial for waivers: Who is legally responsible for who?)
CREATE TABLE relationships (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  guardian_id UUID REFERENCES profiles(id) NOT NULL,
  minor_id UUID REFERENCES profiles(id) NOT NULL,
  relationship_type TEXT CHECK (relationship_type IN ('Parent', 'Legal Guardian', 'Temporary Guardian')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(guardian_id, minor_id)
);

-- 5. MEMBERSHIP PLANS (What you sell)
CREATE TABLE membership_plans (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL, -- e.g., "Family Monthly", "Individual Annual"
  description TEXT,
  price_cents INTEGER NOT NULL,
  billing_interval TEXT CHECK (billing_interval IN ('month', 'year')),
  max_dependents INTEGER DEFAULT 0,
  stripe_price_id TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. SUBSCRIPTIONS (Links a Household to a Plan)
CREATE TABLE subscriptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  household_id UUID REFERENCES households(id) NOT NULL,
  plan_id UUID REFERENCES membership_plans(id) NOT NULL,
  status TEXT CHECK (status IN ('Active', 'Frozen', 'Cancelled', 'Past_Due')),
  start_date DATE NOT NULL,
  end_date DATE
);

-- 7. WAIVERS (The legal documents)
CREATE TABLE waivers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  participant_id UUID REFERENCES profiles(id) NOT NULL, -- Who is climbing?
  signed_by_id UUID REFERENCES profiles(id) NOT NULL, -- Who signed it? (Parent if minor)
  document_version TEXT NOT NULL, -- e.g., "Waiver_v2_2023"
  signature_date TIMESTAMPTZ DEFAULT NOW(),
  expiry_date TIMESTAMPTZ, -- Usually 1 year, or null for lifetime
  is_valid BOOLEAN DEFAULT TRUE,
  pdf_url TEXT -- Link to the actual signed document in Supabase Storage
);

-- 8. PRODUCTS (Retail tracking)
CREATE TABLE products (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL, -- e.g., "Boulderdash Logo T-Shirt"
  sku TEXT, -- Barcode for scanning
  price_cents INTEGER NOT NULL,
  category TEXT CHECK (category IN ('Retail', 'Food/Drink', 'Rental', 'DayPass')),
  is_active BOOLEAN DEFAULT TRUE
);

-- 9. PAYMENT RECEIPTS (The Financial Ledger)
CREATE TABLE payment_receipts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  paid_by_profile_id UUID REFERENCES profiles(id), -- If a person swiped their card at the desk
  household_id UUID REFERENCES households(id), -- If this was an automatic monthly billing charge
  subscription_id UUID REFERENCES subscriptions(id), -- NULL if it was a one-off purchase
  description TEXT,
  amount_cents INTEGER NOT NULL,
  currency TEXT DEFAULT 'USD',
  status TEXT CHECK (status IN ('Pending', 'Succeeded', 'Failed', 'Refunded')),
  stripe_transaction_id TEXT,
  created_by_user_id UUID REFERENCES auth.users(id), -- Which front desk employee rang them up?
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 10. RECEIPT LINE ITEMS (What exactly did they buy?)
CREATE TABLE receipt_line_items (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  receipt_id UUID REFERENCES payment_receipts(id) NOT NULL,
  product_id UUID REFERENCES products(id), 
  subscription_id UUID REFERENCES subscriptions(id), 
  quantity INTEGER DEFAULT 1,
  unit_price_cents INTEGER NOT NULL,
  total_price_cents INTEGER NOT NULL
);

-- 11. GYM CHECKINS (Who is walking through the door?)
CREATE TABLE gym_checkins (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id UUID REFERENCES profiles(id) NOT NULL, -- Who walked through the door? (Adult or Kid)
  scanned_at TIMESTAMPTZ DEFAULT NOW(),
  location TEXT, -- e.g., "Downtown Branch"
  checkin_method TEXT DEFAULT 'qr_scanner' CHECK (checkin_method IN ('qr_scanner', 'front_desk_manual', 'kiosk')),
  status_flag TEXT CHECK (status_flag IN ('Success', 'Waiver Expired', 'Payment Due', 'No Active Pass'))
);

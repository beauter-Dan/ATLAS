// tone: neutral | info | ok | warn | danger
export default function Badge({ tone = 'neutral', children }) {
  return <span className={`chip chip--${tone}`}>{children}</span>;
}

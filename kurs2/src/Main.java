import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.FileSystems;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;

public class Main extends JFrame {
    private final JTextArea resultArea;
    private final JTextField executableFilePathField;
    private final JTextField hashExistsField;
    private final JComboBox<String> hashSelectionComboBox;
    private Connection connection;

    public Main() {
        try {
            String url = "jdbc:mysql://localhost:3306/signas";
            String user = "lucky";
            String password = "DEMON28781d";
            connection = DriverManager.getConnection(url, user, password);
        } catch (SQLException e) {
            e.printStackTrace();
        }

        setTitle("Hash Comparison");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1720, 980);
        setLayout(new FlowLayout());

        JButton calculateHashButton = new JButton("Calculate and Compare Hash");
        JButton addSignatureButton = new JButton("Add Signature to Database");
        resultArea = new JTextArea(10, 30);
        resultArea.setEditable(false);

        JPanel panel = new JPanel();

        executableFilePathField = new JTextField(25);
        panel.add(new JLabel("Executable File: "));
        panel.add(executableFilePathField);

        hashSelectionComboBox = new JComboBox<>();
        try {
            loadHashesFromDatabase();
            panel.add(new JLabel("Select a hash from the database:"));
            panel.add(hashSelectionComboBox);
        } catch (SQLException ex) {
            ex.printStackTrace();
        }

        hashExistsField = new JTextField(25);
        hashExistsField.setEditable(false);
        panel.add(new JLabel("Check if hash exists in the database: "));
        panel.add(hashExistsField);

        add(panel);
        add(calculateHashButton);
        add(addSignatureButton);
        add(new JScrollPane(resultArea));

        calculateHashButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String executableFilePath = executableFilePathField.getText();
                try {
                    String calculatedHash = calculateFileHash(executableFilePath);
                    String selectedHash = (String) hashSelectionComboBox.getSelectedItem();
                    boolean hashExists = isHashExistsInDatabase(calculatedHash);
                    if (calculatedHash.equals(selectedHash)) {
                        resultArea.setText("Hashes match, file found");
                        File file = new File(executableFilePath);
                        resultArea.append("\nFile path: " + file.getAbsolutePath());
                        BasicFileAttributes attr = Files.readAttributes(file.toPath(), BasicFileAttributes.class);
                        resultArea.append("\nCreation time: " + attr.creationTime());
                        resultArea.append("\nLast accessed time: " + attr.lastAccessTime());
                        resultArea.append("\nLast modified time: " + attr.lastModifiedTime());
                    } else {
                        resultArea.setText("Hashes do not match, file not found");
                    }
                    if (hashExists) {
                        hashExistsField.setText("Hash already exists in the database");
                    } else {
                        hashExistsField.setText("Hash does not exist in the database");
                    }
                } catch (IOException | NoSuchAlgorithmException | SQLException ex) {
                    resultArea.setText("Error: " + ex.getMessage());
                }
            }
        });

        addSignatureButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String executableFilePath = executableFilePathField.getText();
                try {
                    String calculatedHash = calculateFileHash(executableFilePath);
                    if (!isHashExistsInDatabase(calculatedHash)) {
                        try (PreparedStatement preparedStatement = connection.prepareStatement("insert into hashes (hash) values (?)")) {
                            preparedStatement.setString(1, calculatedHash);
                            preparedStatement.executeUpdate();
                            resultArea.setText("Signature added to database");
                        }
                    } else {
                        resultArea.setText("Signature already exists in database");
                    }
                } catch (IOException | NoSuchAlgorithmException | SQLException ex) {
                    resultArea.setText("Error: " + ex.getMessage());
                }
            }
        });
    }

    private void loadHashesFromDatabase() throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery("select hash from hashes")) {
            while (resultSet.next()) {
                String hash = resultSet.getString("hash");
                hashSelectionComboBox.addItem(hash);
            }
        }
    }

    private String calculateFileHash(String filePath) throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = Files.newInputStream(Paths.get(filePath)); DigestInputStream dis = new DigestInputStream(is, digest)) {
            byte[] buffer = new byte[8192];
            while (dis.read(buffer) != -1) {
            }
        }
        byte[] hash = digest.digest();
        return bytesToHex(hash);
    }

    private boolean isHashExistsInDatabase(String hash) throws SQLException {
        try (PreparedStatement preparedStatement = connection.prepareStatement("select count(*) from hashes where hash = ?")) {
            preparedStatement.setString(1, hash);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if(resultSet.next()) {
                    int count = resultSet.getInt(1);
                    return count > 0;
                }
            }
        }
        return false;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new Main().setVisible(true);
        });
    }
}
